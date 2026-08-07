# caddy-openappsec: Deploying with the Real open-appsec Agent

This guide covers production deployment: running caddy-openappsec against the
real open-appsec nano engine (`ghcr.io/openappsec/agent`) over the linux
shared-memory (`shm`) transport, instead of the mock engine over TCP.

For the local mock-engine quick start, see `README.md`. For the byte-level
wire protocol, see `docs/attachment-protocol.md`. For the full configuration
reference, see `docs/integration.md` section 4.

---

## 1. How caddy talks to the real agent

The module does **not** talk to the agent over the network. On linux, the
`shm` transport uses three channels, all backed by the host's `/dev/shm`
(tmpfs):

```
┌───────────────────┐   registration (AF_UNIX)              ┌─────────────────────┐
│  caddy (module)   │ ─────────────────────────────────────▶│                     │
│                   │   /dev/shm/check-point/               │  ghcr.io/openappsec │
│                   │     cp-nano-attachment-registration   │  /agent (nano)      │
│                   │ ─── handshake G.1/G.2 ───────────────▶│                     │
│                   │ ◀── verdict signal path ──────────────│                     │
│                   │                                       │                     │
│                   │   shared-memory ring queues (O_RDWR)  │                     │
│                   │ ─────────────────────────────────────▶│  REQUEST_START      │
│                   │   /dev/shm/__cp_nano_<family>_        │  frames in tx queue  │
│                   │     shared_memory_<in|out>__          │                     │
│                   │ ◀─────────────────────────────────────│  verdict frames      │
│                   │                                       │  in rx queue         │
│                   │   keep-alive (AF_UNIX)                │                     │
│                   │ ─────────────────────────────────────▶│  expiration socket   │
│                   │   ...-expiration-socket               │  (G.3)               │
└───────────────────┘                                       └─────────────────────┘
```

Concretely (`internal/app/dialer_linux.go`, `internal/transport/linux/`):

1. **Registration** — `DialSignal` connects to the AF_UNIX registration socket
   and completes the two-phase handshake (protocol doc G.1/G.2). Phase 1
   returns the verdict signal path; phase 2 sends the family name.
2. **Traffic** — `OpenRing` opens the two one-way shared-memory ring queues
   named `__cp_nano_<unique_id>_shared_memory_<dir>__` in `/dev/shm`
   (`internal/transport/linux/ring_linux.go`), where `<unique_id>` is
   `config.EngineConfig.UniqueID()` = `<family>_<worker_id+1>` — the same value
   sent in the phase-2 comm frame. The agent creates and sizes the files under
   that id (`initIpc(curr_instance_unique_id)`, `nginx_attachment.cc:537-538`);
   the module only opens them `O_RDWR`. Request metadata goes in the tx queue,
   verdicts come back in the rx queue.
3. **Keep-alive** — `DialKeepAlive` uses a separate raw AF_UNIX socket
   (`...-expiration-socket`, protocol doc G.3), never the ring, so foreign
   frames cannot corrupt the shared-memory queues.

The three signal paths default to the standard agent locations
(`internal/config/config.go`):

| Setting | Default |
|---|---|
| `registration_socket` | `/dev/shm/check-point/cp-nano-attachment-registration` |
| `verdict_signal_path` | `/dev/shm/check-point/cp-nano-http-transaction-handler` |
| `keep_alive_path` | `/dev/shm/check-point/cp-nano-attachment-registration-expiration-socket` |

So a real deployment only needs `family_name` — everything else defaults to
paths the agent already listens on.

---

## 2. Prerequisites

- **A linux host.** The `shm` transport only compiles on linux
  (`internal/transport/linux`, `//go:build linux`). On Windows/macOS it is an
  unreachable stub that fails open — the module compiles and runs, but never
  inspects. Docker Desktop's `/dev/shm` semantics are unreliable; run on a
  real linux host (bare metal, VM, or cloud instance).
- **Docker with compose** on that host.
- **An open-appsec agent token** for `ghcr.io/openappsec/agent`
  (register at the open-appsec portal / your SaaS account).
- **Pin the agent version.** Use `ghcr.io/openappsec/agent:1.1.33`, **not**
  `:latest`. The `:latest` tag has shipped shared-memory protocol revisions
  that break every attachment (nginx, NPM, and this module alike): the agent
  stays "running" but every attachment logs `isCorruptedShmem` and no
  inspection happens. Pin the tag and add `--no-upgrade` to the agent command
  so the container cannot drift past the pinned version.

---

## 3. Quick start

`docker-compose.agent.yml` in the repo root wires both containers with
`ipc: host` so they share the host's `/dev/shm` — the one requirement that
makes the shm transport work at all (sharing only `/dev/shm/check-point` is
**not** enough: the ring queues live directly in `/dev/shm`).

```
export APPSEC_TOKEN="<your agent token>"
docker compose -f docker-compose.agent.yml up -d
curl http://localhost:8080/
```

The `Caddyfile.agent` mounted into the caddy container is minimal:

```
:80 {
	route {
		openappsec {
			engine {
				family_name caddy
			}
		}
		respond "hello from origin"
	}
}
```

Notes:

- The `route` block is required. Caddy sorts top-level directives by its own
  order, where `respond` precedes `reverse_proxy` — and the module registers
  itself before `reverse_proxy` — so at the top level the WAF would run
  *after* `respond` and never see the request. Inside `route`, the written
  order is preserved (the e2e harness relies on the same pattern,
  `internal/e2e/harness.go`).
- An empty `transport` resolves to `shm` on linux (the platform default), so
  it can be omitted.
- `family_name` (with the worker id) names the ring queues the agent creates
  via `EngineConfig.UniqueID()`. It must be unique per Caddy instance on a
  host — two Caddy processes with the same `family_name` fight over the same
  queues.
- Replace `respond "hello from origin"` with `reverse_proxy` to your real
  backend (the directive order already places openappsec before it).

---

## 4. Verifying the deployment

1. **Agent is up and sees the attachment.** The agent container logs
   registration activity; `docker compose -f docker-compose.agent.yml logs
   agent` should show the attachment registering and no
   `isCorruptedShmem` errors.
2. **The shm files exist.** On the host:

   ```
   ls -la /dev/shm/check-point/                      # the three AF_UNIX sockets
   ls -la /dev/shm/ | grep cp_nano                  # __cp_nano_<unique_id>_shared_memory_*
   ```

   If the ring files are missing, the agent has not registered the family
   (family name mismatch or wrong agent version).
3. **Traffic is inspected.** `curl http://localhost:8080/` with a payload that
   triggers a policy (e.g. a SQL injection test string) should produce the
   configured block page (default 403). A request that is policy-compliant
   passes through to the origin. Watch caddy's logs for the verdict.
4. **Keep-alive holds the registration.** Leave it running; if the agent
   starts expiring the registration, lower `keep_alive_interval_ms` below the
   agent's 300000 ms window.

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `isCorruptedShmem` in agent logs, no inspection | `:latest` agent with a shmem protocol incompatible with the module | Pin `ghcr.io/openappsec/agent:1.1.33` + `--no-upgrade` |
| `No such file or directory` on the signal socket | Container `/dev/shm` not shared with the agent | `ipc: host` on both services; check `/dev/shm/check-point` is the same mount in both |
| Ring files `__cp_nano_*_shared_memory_*__` never appear | Family name mismatch, or agent never registered the family | Same `family_name` as expected by the agent config; restart the agent after changing it |
| `open write queue "...__cp_nano_rx_shared_memory_<family>__": no such file` | Module opened the bare family name; the agent names queues `<family>_<worker_id+1>` | Use the fixed image (`>= sha-6972947`) which derives the queue name from `UniqueID()`; wipe stale `/dev/shm/__cp_nano_*` first |
| Requests pass through, no block pages | Fail-open default and the engine is unreachable | Confirm the agent container is running and `/dev/shm` is shared; look for the "failing open" warning in caddy logs |
| `engine shared-memory transport is only available on linux` | Running on Windows/macOS | This stack is linux-only; use the mock engine over `transport socket` locally |
| Registrations expire / engine forgets the attachment | Keep-alive interval at or above the engine's 300000 ms window | Lower `keep_alive_interval_ms` |
| Two Caddy instances collide | Same `family_name` on one host | Give each instance a unique `family_name` |

---

## 6. Differences from the mock-engine demo

| | Mock demo (`docker-compose.yml`) | Real agent (`docker-compose.agent.yml`) |
|---|---|---|
| Engine image | `ghcr.io/580132/caddy-openappsec-mockengine` | `ghcr.io/openappsec/agent:1.1.33` |
| Transport | `socket` (TCP) | `shm` (linux shared memory) |
| Cross-container requirement | none (plain network) | `ipc: host` (shared `/dev/shm`) |
| Config | explicit `tcp://` addresses | defaults only, `family_name` required |
| Verdicts | scripted scenarios | real policy engine |
| Platform | any | linux only |

The two stacks exercise the same application protocol (handshake, frames,
verdicts) — the e2e suite covers that over `socket`. The shm path differs
only in how bytes move (mmap'd ring queues vs TCP frames); this guide is the
documented bridge to the real engine.
