// Command mockengine runs the scriptable mock open-appsec engine as a
// standalone process for local E2E. It serves the engine over the transport
// chosen with -transport: the default "memory" mode listens on an in-memory
// address (a plain registry key — no sockets, no shared memory), while
// "socket" mode binds a real TCP listener for cross-process E2E. Either way
// it answers the two-phase registration handshake, and replies to requests
// per the chosen scenario:
//
//	allow   — ACCEPT every request
//	block   — DROP every request with a custom 403 web response
//	inject  — INJECT a script tag into every response body
//	flaky   — close each connection after N request frames (default 1),
//	          exercising the app's reconnect/backoff path
//	down    — complete the handshake but never reply to requests,
//	          exercising the app's fail-open timeout budget
//
// Every received frame is hex-dumped with a one-line parsed meaning.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/580132/caddy-openappsec/internal/mock"
	"github.com/580132/caddy-openappsec/internal/protocol"
	"github.com/580132/caddy-openappsec/internal/transport/socket"
)

// blockWebResponse is the DROP response for the "block" scenario.
func blockWebResponse() *protocol.WebResponse {
	return &protocol.WebResponse{
		Type:       protocol.WebResponseCustom,
		StatusCode: 403,
		Title:      "Blocked by mock engine",
		Body:       "This request was blocked by the mock open-appsec engine.",
	}
}

// injectVerdict is the INJECT response for the "inject" scenario.
func injectVerdict() protocol.Verdict {
	return protocol.Verdict{
		Kind: protocol.VerdictInject,
		Injections: []protocol.Injection{
			{
				InjectionPos:    protocol.InjectPosIrrelevant,
				ModType:         protocol.ModInject,
				IsHeader:        false,
				OrigBufferIndex: 0,
				Data:            []byte("<mock-inject>"),
			},
		},
	}
}

// configureScenario wires the engine's control API to the scenario.
func configureScenario(eng *mock.Engine, scenario string, requests int) error {
	switch scenario {
	case "allow":
		eng.SetResponder(func(uint32) protocol.Verdict { return protocol.Verdict{Kind: protocol.VerdictAccept} })
	case "block":
		eng.SetResponder(func(uint32) protocol.Verdict {
			return protocol.Verdict{Kind: protocol.VerdictDrop, WebResponse: blockWebResponse()}
		})
	case "inject":
		eng.SetResponder(func(uint32) protocol.Verdict { return injectVerdict() })
	case "flaky":
		eng.SetFlakyAfter(requests)
	case "down":
		eng.SetVerdictsEnabled(false)
	default:
		return fmt.Errorf("unknown scenario %q (want allow|block|inject|flaky|down)", scenario)
	}
	return nil
}

// dumpLoop prints each newly received frame with a spaced hex dump and its
// one-line meaning until ctx is done.
func dumpLoop(eng *mock.Engine) {
	seen := 0
	for {
		time.Sleep(100 * time.Millisecond)
		frames := eng.ReceivedFrames()
		for _, f := range frames[seen:] {
			log.Printf("frame %d: %-48s %s", seen+1, spacedHex(f.Hex), f.Meaning)
		}
		seen = len(frames)
	}
}

// spacedHex formats a lowercase hex string with a space between bytes,
// e.g. "030001000000" -> "03 00 01 00 00 00".
func spacedHex(h string) string {
	parts := make([]string, 0, len(h)/2)
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, " ")
}

func main() {
	addr := flag.String("addr", "mock-engine", "address to listen on: in-memory registry key with -transport memory, or a TCP address like \"tcp://127.0.0.1:0\" with -transport socket")
	scenario := flag.String("scenario", "allow", "scenario: allow|block|inject|flaky|down")
	requests := flag.Int("requests", 1, "flaky scenario: close each connection after N request frames")
	transportFlag := flag.String("transport", "memory", "transport: memory (in-memory registry key) | socket (real TCP listener)")
	flag.Parse()

	var (
		eng       *mock.Engine
		effective string
	)
	switch *transportFlag {
	case "memory":
		var err error
		eng, err = mock.New(*addr)
		if err != nil {
			log.Fatalf("mockengine: %v", err)
		}
		effective = *addr
	case "socket":
		l, err := socket.Listen(*addr)
		if err != nil {
			log.Fatalf("mockengine: %v", err)
		}
		effective = l.Addr() // canonical "tcp://host:port", real port when 0 was requested
		eng, err = mock.NewWithListener(l)
		if err != nil {
			_ = l.Close()
			log.Fatalf("mockengine: %v", err)
		}
	default:
		log.Fatalf("mockengine: unknown transport %q (want memory|socket)", *transportFlag)
	}
	defer eng.Close()
	if err := configureScenario(eng, *scenario, *requests); err != nil {
		log.Fatal(err)
	}

	log.Printf("mock engine listening on %q (transport %s, scenario %s)", effective, *transportFlag, *scenario)
	go dumpLoop(eng)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("received signal, shutting down")
}
