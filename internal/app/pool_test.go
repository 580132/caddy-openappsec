package app

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Test_Pool_acquire_twice_release_once_keeps_conn verifies the refcount
// semantics: a second Acquire shares the existing connection, and a single
// Release does not tear it down.
func Test_Pool_acquire_twice_release_once_keeps_conn(t *testing.T) {
	// Given a fake engine and a pool
	cfg := testConfig(t, "pool-share.sock")
	f := newFakeEngine(t, cfg)
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})

	// When the same address is acquired twice and released once
	c1, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	c2, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)

	// Then both acquisitions share one connection
	if c1 != c2 {
		t.Fatalf("acquire returned different conns: %p != %p", c1, c2)
	}
	if c2.Closed() {
		t.Fatal("conn closed while still referenced")
	}

	p.Release(cfg.RegistrationSocket)
	if c1.Closed() {
		t.Fatal("conn closed after a single release")
	}
	if _, ok := p.entries[cfg.RegistrationSocket]; !ok {
		t.Fatal("entry removed while still referenced")
	}

	// And the last release closes it and removes the entry
	p.Release(cfg.RegistrationSocket)
	if !c1.Closed() {
		t.Fatal("conn not closed after last release")
	}
	if _, ok := p.entries[cfg.RegistrationSocket]; ok {
		t.Fatal("entry not removed after last release")
	}
}

// Test_Pool_concurrent_acquire_shares_one_conn verifies that an acquire storm
// against a cold address dials exactly once and hands every caller the same
// live connection.
func Test_Pool_concurrent_acquire_shares_one_conn(t *testing.T) {
	// Given a fake engine and a pool
	cfg := testConfig(t, "pool-storm.sock")
	f := newFakeEngine(t, cfg)
	defer f.close()
	p := NewPool(cfg, &memoryDialer{cfg: cfg})

	const workers = 32
	conns := make([]*Conn, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = p.Acquire(context.Background(), cfg.RegistrationSocket)
		}(i)
	}
	wg.Wait()

	// Then every acquire succeeded and shares one connection
	for i := 0; i < workers; i++ {
		requireNoError(t, errs[i])
		if conns[i] != conns[0] {
			t.Fatalf("acquire %d returned a different conn", i)
		}
	}

	// And the engine saw exactly one dial (one handshake).
	// One connection is on f.connections; a second dial would block on the
	// handshake reply, so a short poll proves only one handshake happened.
	select {
	case <-f.connections:
		// first (only) dial
	default:
		t.Fatal("engine did not receive a dial")
	}
	select {
	case <-f.connections:
		t.Fatal("engine received more than one dial")
	case <-time.After(50 * time.Millisecond):
	}

	// Clean up: release every acquire.
	for i := 0; i < workers; i++ {
		p.Release(cfg.RegistrationSocket)
	}
	if !conns[0].Closed() {
		t.Fatal("conn not closed after releasing all references")
	}
}

// Test_Pool_acquire_error_is_not_cached verifies a failed first dial does not
// poison the address: a later Acquire retries and succeeds once the engine is
// reachable.
func Test_Pool_acquire_error_is_not_cached(t *testing.T) {
	// Given a pool whose address has no engine yet
	cfg := testConfig(t, "pool-retry.sock")
	p := NewPool(cfg, &memoryDialer{cfg: cfg})

	// When the first acquire targets a dead address
	_, err := p.Acquire(context.Background(), cfg.RegistrationSocket)

	// Then it fails
	requireError(t, err, "no listener")
	if _, ok := p.entries[cfg.RegistrationSocket]; ok {
		t.Fatal("failed entry left in the pool")
	}

	// And once the engine comes up, a fresh acquire succeeds
	f := newFakeEngine(t, cfg)
	defer f.close()
	c, err := p.Acquire(context.Background(), cfg.RegistrationSocket)
	requireNoError(t, err)
	defer func() {
		p.Release(cfg.RegistrationSocket)
	}()
	if c.Closed() {
		t.Fatal("conn closed on acquisition")
	}
}

// Test_Pool_release_without_acquire_is_safe verifies Release on an unknown
// address is a no-op, not a panic.
func Test_Pool_release_without_acquire_is_safe(t *testing.T) {
	// Given
	cfg := testConfig(t, "pool-noref.sock")
	p := NewPool(cfg, &memoryDialer{cfg: cfg})

	// When/Then
	p.Release(cfg.RegistrationSocket) // must not panic
}
