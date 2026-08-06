package app

import (
	"context"
	"time"

	"github.com/yourname/caddy-openappsec/internal/protocol"
)

// keepAliveLoop sends keep-alive frames (§G.3) over the dedicated keep-alive
// socket at cfg.KeepAliveIntervalMs. The socket is dialed lazily on the first
// tick; a failed send (dead engine) drops it so the next tick redials, and the
// send cadence backs off exponentially, capped by the reconnect backoff bounds.
func (c *Conn) keepAliveLoop() {
	defer c.wg.Done()
	interval := time.Duration(c.cfg.KeepAliveIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = 300 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	min := time.Duration(c.cfg.ReconnectBackoffMinMs) * time.Millisecond
	max := time.Duration(c.cfg.ReconnectBackoffMaxMs) * time.Millisecond
	attempt := 0

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			if err := c.keepAliveSend(); err != nil {
				attempt++
				delay := backoffDelay(min, max, attempt)
				select {
				case <-time.After(delay):
				case <-c.stop:
					return
				}
			} else {
				attempt = 0
			}
		}
	}
}

// keepAliveSend dials the keep-alive socket on first use and sends one
// keep-alive frame. On failure the socket is dropped for the next tick.
func (c *Conn) keepAliveSend() error {
	c.kaMu.Lock()
	ka := c.kaConn
	if ka == nil {
		nc, err := c.dialer.DialKeepAlive(context.Background())
		if err != nil {
			c.kaMu.Unlock()
			return err
		}
		c.kaConn = nc
		ka = nc
	}
	c.kaMu.Unlock()

	payload := protocol.KeepAlive{
		WorkerID:   uint8(c.cfg.WorkerID),
		FamilyName: c.cfg.FamilyName,
	}.Encode()
	if err := ka.Send(context.Background(), payload); err != nil {
		c.kaMu.Lock()
		if c.kaConn == ka {
			c.kaConn = nil
		}
		c.kaMu.Unlock()
		_ = ka.Close()
		return err
	}
	return nil
}
