# caddy-openappsec: Integration and Operations Guide

This is the deep technical companion to the caddy-openappsec Caddy module.
It describes how the module is put together, how it talks to the open-appsec
nano engine, what every configuration knob does, and how the system behaves
when the engine is up, slow, or gone. Every number in this document is taken
from the source (`internal/config/config.go`) or from the wire-protocol
specification (`docs/attachment-protocol.md`). The byte-level protocol, frame
formats, and handshake sequences are specified there; this document explains
how the Go module uses them.

Readers who want the user-facing quick start should read `README.md`. Readers
who want to implement or modify a transport should read
`docs/attachment-protocol.md` alongside this guide.

---

## 1. Purpose

The module is a Caddy v2 HTTP middleware (`http.handlers.openappsec`) that
runs every request through the open-appsec nano engine. For each request it
opens an inspection session, sends the request metadata over the configured
transport, waits for a verdict, and then either blocks the request, modifies
it, or forwards it to the next handler. The default posture is fail-open: if
the engine cannot be reached or does not answer in time, traffic passes
through untouched. Fail-closed is available as an explicit opt-in.

The module also registers a Caddy application module (`http.openappsec`) that
owns the process-global engine connection pool. Both module IDs are
registered at import time by the blank imports in `imports.go`
(`internal/app`, `internal/handler`).

The current implementation inspects and acts on the request side only. The
response path buffers the origin's body and re-emits it after a verdict, but
does not yet submit the response to the engine for a response verdict.
Response inspection is implemented in the app layer
(`app.FailOpenPolicy.AcquireResponseVerdict`, `app.Conn.SendResponse`) and
covered by unit tests, but the handler does not call it yet.

---

## 2. Architecture

The request path runs through five layers. From outside in:

1. The Caddy handler chain, where the `openappsec` directive is ordered
   before `reverse_proxy` (`internal/handler/caddyfile.go`, registered with
   `RegisterDirectiveOrder("openappsec", Before, "reverse_proxy")`).
2. `handler.Handler`, the middleware. It buffers the request body, acquires a
   verdict, enforces it, and forwards.
3. `app.FailOpenPolicy`, the verdict surface. It owns the connection
   lifecycle (Acquire/Release), hides reconnects, and converts engine
   failure into an ACCEPT verdict when failing open.
4. `app.Pool`, a process-global, reference-counted registry of live engine
   connections keyed by registration address. The first acquirer dials and
   handshakes; everyone else shares the connection. A Caddy reload that
   re-registers the same address reuses the connection instead of dialing a
   second one.
5. `app.Dialer` + transport. `NewDialer` (`internal/app/dialer.go`)
   dispatches on `cfg.Transport`: `memory` selects the in-process pipe
   transport, `socket` selects cross-process TCP, and `shm` (or the empty
   value, the platform default) selects the linux shared-memory transport on
   linux and a fail-open stub everywhere else.

Every dialer runs the same two-phase registration handshake
(`internal/app/handshake.go`, protocol doc section G.1 and G.2): phase 1
sends `[attachment_type][worker_id+1][workers][family_name_size][family_name]`
and reads back `[path_length][path]` (the verdict signal path); phase 2 sends
`[uid_size][uid][user_id u32][group_id u32]` and reads a 1-byte ack. Only the
linux shm dialer uses the returned path (to open the shared-memory ring); the
memory and socket dialers keep using the connection they already hold.

```
                     HTTP request
                          |
                          v
              caddyhttp handler chain
                          |
                          v
        handler.Handler.ServeHTTP  (http.handlers.openappsec)
          | 1. readRequestBody: buffer ORIGINAL bytes (compression intact)
          | 2. AcquireVerdict(RequestData{Start: requestStart(r)})
          | 3. switch verdict.Kind:
          |      DROP / CUSTOM_RESPONSE  -> ModePrevent: writeBlock
          |                                 ModeLearn:  log, then forward
          |      INJECT                  -> applyInjections, forward
          |      ACCEPT / other          -> forward
          | 4. forward: wrap in responseWriter (ResponseBufferLimit), next,
          |             finalize re-emits buffered body
          v
   app.FailOpenPolicy.AcquireVerdict
          |
          |  pool.Acquire(registration_socket)   [refcount, shared conn]
          |  Conn.SendRequest -> REQUEST_START frame
          |  await: poll verdict until verdictBudget
          |      budget = MaxRetriesForVerdict x ReqMaxProcessingMs
          |      poll sleep = FailOpenTimeoutMs, hold sleep =
          |      HoldVerdictRetries x HoldVerdictPollingMs
          |  on error / timeout -> fail-open: ACCEPT verdict (default)
          v
      app.Pool (process-global, per address)
          |
          |  Dialer.Dial -> two-phase handshake (protocol doc G.1/G.2)
          v
   transport: memory (in-process registry) | socket (TCP) | shm (linux)
          |  one Send == one Recv, opaque payloads
          v
        open-appsec nano engine
          |  verdict replies: ACCEPT / DROP / CUSTOM_RESPONSE / INJECT
          |  keep-alive: separate raw socket, interval KeepAliveIntervalMs
          v
      verdict flows back; fail-open posture lets traffic through
      when the engine is unreachable or silent past the budget
```

The `http.openappsec` app module (`internal/app/app.go`) is the second entry
point. Its `Start` lazily acquires the pooled connection (so the attachment
registers before the first request) and returns an error only when fail-open
is explicitly disabled; `Stop` and `Cleanup` release the pooled connection.
The handler uses the same `GlobalPool`, so both surfaces share one connection
per registration address.

---

## 3. Transports in depth

The transport knob lives on `EngineConfig.Transport`. It is resolved in
`app.NewDialer`, not in config validation, so an empty value is valid and
means "platform default".

### 3.1 memory

In-process pipes addressed by a plain string (`internal/transport/memory`).
`Listen(addr)` registers the address in a package-level map; `Dial(addr)`
creates a connection pair and queues it for `Accept`. No sockets, no shared
memory.

Used by unit tests and by the mock engine's default `-transport memory` mode.
The address is just a registry key, so it is meaningful only inside one
process.

### 3.2 socket

Cross-process TCP transport (`internal/transport/socket`). Used by the mock
engine CLI (`-transport socket`) and by local end-to-end runs.

Framing: every payload is one frame, a 4-byte little-endian length prefix
followed by the payload bytes (`internal/transport/socket/frame.go`). One
`Send` writes exactly one frame, which the peer reads back as exactly one
`Recv`. Frames are capped at 256 MiB (`maxFrameSize = 256 << 20`); a length
prefix above the cap is rejected without being allocated, and a frame that
declares more bytes than the stream delivers is reported as truncated. The
transport never interprets payload bytes; framing preserves the
one-Send-is-one-Recv contract of `transport.EngineConn`
(`internal/transport/transport.go`).

Addresses: `"tcp://host:port"` or a bare `"host:port"`; both name a TCP
endpoint. The `"unix://"` scheme is reserved for a future Unix-socket
variant and is rejected with an explicit error on every platform, never
silently falling back to TCP. A port of 0 requests an ephemeral port;
`Listener.Addr()` reports the canonical `"tcp://host:port"` form with the
actual port, so a dialer can be handed the listener's address directly.
Dials are bounded by a 30 s timeout (`dialTimeout` in
`internal/transport/socket/socket.go`).

### 3.3 shm (linux production)

Linux-only shared-memory transport (`internal/transport/linux`). This is the
production path. `shmDialer.Dial` connects to the registration signal socket
(AF_UNIX), completes the two-phase handshake to learn the verdict signal
path, then opens the shared-memory ring queues for request and verdict
traffic (`internal/app/dialer_linux.go`, protocol doc sections D and G). The
ring files are named `__cp_nano_%s_shared_memory_%s__` and messages move
through the management-segment framing, one Send is one Recv unit on the
peer, capped at `max_write_size` (0xfffc). Keep-alive is a separate raw
AF_UNIX socket to the keep-alive path, never the ring.

On non-linux builds `newShmDialer` returns a stub whose `Dial` and
`DialKeepAlive` always error with
`app: engine shared-memory transport is only available on linux, running on
<GOOS>` (`internal/app/dialer_stub.go`). That error is routed through the
fail-open policy: the engine is unreachable, so requests pass through. This
stub is what an empty `transport` resolves to on non-linux, which is why an
unconfigured module on a Windows or macOS dev box does not block traffic. It
is also why a `shm` config on a non-linux host produces no block pages, just
allow-through traffic.

### 3.4 Choosing a transport

| Use case | transport |
|---|---|
| Unit tests, in-process mock | `memory` |
| Local end-to-end against the mock engine CLI | `socket` |
| Production on linux against the nano engine | `shm` (or empty) |
| Non-linux host | `socket` (with the mock engine) or empty (fail-open stub) |

---

## 4. Configuration reference

Every value below is verified against `internal/config/config.go`
(engine defaults), `internal/config/engine.go` (fields, JSON tags,
validation), and `internal/config/handler.go` plus `internal/handler/*.go`
(handler fields). The Caddyfile parser (`internal/handler/caddyfile.go`)
exposes a subset of the engine options; everything else is set through Caddy
JSON. Size arguments in the Caddyfile accept a bare byte count or a binary
suffix (KB, MB, GB, KiB, MiB, GiB, case-insensitive; 1 MiB = 1048576 bytes).

### 4.1 Engine options (`engine { ... }` in Caddyfile, `engine` in JSON)

| Caddyfile name | JSON key | Type | Default | Description |
|---|---|---|---|---|
| `transport` | `transport` | string | empty (= platform default) | `memory`, `socket`, `shm`. Empty resolves to linux shm, or the fail-open stub elsewhere. |
| `registration_socket` | `registration_socket` | string | `DefaultRegistrationSocket`: `/dev/shm/check-point/cp-nano-attachment-registration` | Engine's registration endpoint (SHARED_REGISTRATION_SIGNAL_PATH, protocol doc G.1). For socket transport, a TCP address. |
| `keep_alive_path` | `keep_alive_path` | string | `DefaultKeepAlivePath`: `/dev/shm/check-point/cp-nano-attachment-registration-expiration-socket` | Engine's keep-alive endpoint (SHARED_KEEP_ALIVE_PATH, protocol doc G.3). |
| `verdict_signal_path` | `verdict_signal_path` | string | `DefaultVerdictSignalPath`: `/dev/shm/check-point/cp-nano-http-transaction-handler` | Verdict signal path (SHARED_VERDICT_SIGNAL_PATH, protocol doc G.2). Used by the linux shm dialer to open the ring after handshake; ignored by memory and socket dialers. |
| `family_name` | `family_name` | string | none, required | Identifies this attachment family in registration and keep-alive (protocol doc G.1, G.3). `Validate` fails if empty. No default. |
| `worker_id` | `worker_id` | int | 0 | Zero-based worker index. Sent as `worker_id + 1` in the registration frame (nginx convention) and raw (uint8) in keep-alive frames. Must be >= 0. |
| `workers` | `workers` | int | `DefaultWorkers`: 1 | Number of attachment worker processes, sent in the registration frame. Must be > 0. |
| `attachment_type` | `attachment_type` | string | `DefaultAttachmentType`: `"nginx"` | Family presented to the engine (protocol doc G.1). The engine defines an id for nginx but none for Caddy, so `nginx` is the only supported value. |
| `keep_alive_interval_ms` | `keep_alive_interval_ms` | int | `DefaultKeepAliveIntervalMs`: 300000 | Keep-alive interval in ms. The engine expires a registration not kept alive within 300000 ms, so keep this below the expiry window. |
| `registration_timeout_ms` | `registration_timeout_ms` | int | `DefaultRegistrationTimeoutMs`: 100 | Bounds the registration handshake and the boot-time reachability check. |
| `reconnect_backoff_min_ms` | `reconnect_backoff_min_ms` | int | `DefaultReconnectBackoffMinMs`: 100 | Initial reconnect and keep-alive failure backoff. |
| `reconnect_backoff_max_ms` | `reconnect_backoff_max_ms` | int | `DefaultReconnectBackoffMaxMs`: 5000 | Backoff ceiling; must be >= `reconnect_backoff_min_ms`. |
| `fail_open_timeout_ms` | `fail_open_timeout_ms` | int | `DefaultFailOpenTimeoutMs`: 50 | Poll interval while waiting for a verdict (sleep between non-verdict frames). |
| (JSON only) | `fail_open_hold_timeout_ms` | int | `DefaultFailOpenHoldTimeoutMs`: 150 | Intended hold-verdict budget. Parsed and validated but not consumed by the current fail-open policy, which derives the hold delay from `hold_verdict_retries` x `hold_verdict_polling_ms`. |
| `req_max_processing_ms` | `req_max_processing_ms` | int | `DefaultReqMaxProcessingMs`: 3000 | Request inspection time bound, one factor of the verdict budget. |
| `res_max_processing_ms` | `res_max_processing_ms` | int | `DefaultResMaxProcessingMs`: 3000 | Response inspection time bound (reserved for response inspection). |
| (JSON only) | `min_retries_for_verdict` | int | `DefaultMinRetriesForVerdict`: 3 | Minimum verdict poll retries. |
| (JSON only) | `max_retries_for_verdict` | int | `DefaultMaxRetriesForVerdict`: 15 | Maximum verdict poll retries; must be >= `min_retries_for_verdict`. With `req_max_processing_ms` it forms the verdict budget (default 15 x 3000 ms = 45000 ms). |
| (JSON only) | `hold_verdict_retries` | int | `DefaultHoldVerdictRetries`: 3 | Times a REQUEST_DELAYED_VERDICT is re-polled. |
| (JSON only) | `hold_verdict_polling_ms` | int | `DefaultHoldVerdictPollingMs`: 1 | Delay between delayed-verdict re-polls. With `hold_verdict_retries` it is the per-delay sleep (default 3 x 1 = 3 ms). |
| (JSON only) | `body_size_trigger` | int | `DefaultBodySizeTrigger`: 200000 | Body size above which the nginx reference switches to the trigger path; retained for parity. |
| (JSON only) | `decompression_pool_size` | int | `DefaultDecompressionPoolSize`: 262144 | Response decompression pool size (protocol doc J). |
| (JSON only) | `recompression_pool_size` | int | `DefaultRecompressionPoolSize`: 16384 | Response recompression pool size (protocol doc J). |
| (JSON only) | `is_brotli_inspection_enabled` | bool | false | Gates brotli decompression (protocol doc J). No default constant; zero value false. |
| `log_level` | `log_level` | string | `DefaultLogLevel`: `"info"` | Attachment log level. |
| (JSON only) | `fail_open` | bool | true | Engine-level fail-open switch. When false, the policy surfaces engine errors instead of converting them to ACCEPT. Tri-state in JSON: omitted means true. |

The `EngineConfig.Validate` rules (`internal/config/engine.go`): `family_name`
must be non-empty; `attachment_type` must be in `["nginx"]`; a non-empty
`transport` must be in `["memory", "socket", "shm"]`; `worker_id` must be
>= 0; `workers` and every `*_ms`, `min_retries_for_verdict`,
`max_retries_for_verdict`, `hold_verdict_retries`,
`hold_verdict_polling_ms`, `body_size_trigger`, `decompression_pool_size`,
`recompression_pool_size` must be > 0; `reconnect_backoff_max_ms` must be
>= `reconnect_backoff_min_ms`; `max_retries_for_verdict` must be
>= `min_retries_for_verdict`. Violations are joined into one descriptive
error.

### 4.2 Handler options (top level of the `openappsec` directive)

| Caddyfile name | JSON key | Type | Default | Description |
|---|---|---|---|---|
| `engine` | `engine` | object | engine defaults | Nested engine config, section 4.1. |
| `mode` | `mode` | string | `DefaultMode`: `"prevent"` | `prevent` enforces verdicts; `learn` logs would-block requests (info) and forwards them. |
| `body_buffer_limit` | `body_buffer_limit` | int | `DefaultBodyBufferLimit`: 10 MiB (10485760) | Request body bytes buffered for inspection. Bodies larger than this are still buffered and a debug log is emitted; the origin always receives the original bytes. Must be > 0. |
| `response_buffer_limit` | `response_buffer_limit` | int | `DefaultResponseBufferLimit`: 4 MiB (4194304) | Response body bytes buffered before re-emission. Must be > 0. |
| `block_status_code` | `block_status_code` | int | `DefaultBlockStatusCode`: 403 | Status for synthesized block pages. Must be in [400, 599]. |
| `block_page_title` | `block_page_title` | string | `DefaultBlockPageTitle`: `"Request blocked"` | Title of the synthesized block page. |
| `block_page_body` | `block_page_body` | string | `DefaultBlockPageBody`: `"Your request was blocked by the security policy."` | Body paragraph of the synthesized block page. |
| `fail_open` | `fail_open` | bool | unset = true | Handler-level fail-open switch. When explicitly false, engine failure produces a 502 and Provision checks engine reachability at boot. Tri-state in JSON: omitted means true. |
| `skip_compressed_body_inspection` | `skip_compressed_body_inspection` | bool | false | Gates the compressed-body inspection helper. The helper is not wired into `ServeHTTP` in this wave, so the origin receives original bytes regardless. |
| `custom_headers` | `custom_headers` | object | none | Extra headers for block responses. Parsed and validated, but not yet attached by `writeBlock` in this wave. |

`Handler.Validate` (`internal/handler/handler.go`): mode must be `prevent` or
`learn`; `body_buffer_limit` and `response_buffer_limit` must be > 0;
`block_status_code` must be in [400, 599].

---

## 5. Configuration examples

### 5.1 Caddyfile

```
:8080 {
    openappsec {
        engine {
            # transport socket connects to the mock engine CLI; use shm (or
            # omit transport) for the linux production engine.
            transport socket
            registration_socket tcp://127.0.0.1:52743
            keep_alive_path     tcp://127.0.0.1:52743
            family_name         caddy
        }
        mode prevent
        body_buffer_limit     10MiB
        response_buffer_limit 4MiB
        block_status_code     403
        block_page_title      "Request blocked"
        block_page_body       "Your request was blocked by the security policy."
        fail_open             true
        custom_headers {
            X-WAF-Engine openappsec
        }
    }

    reverse_proxy 127.0.0.1:8081
}
```

The directive is registered to run before `reverse_proxy`, so the verdict
land before the upstream request is sent.

### 5.2 Caddy JSON

The same config adapted. JSON keys match the struct tags exactly
(`internal/handler/handler.go`, `internal/config/engine.go`).

```json
{
  "handler": "openappsec",
  "engine": {
    "transport": "socket",
    "registration_socket": "tcp://127.0.0.1:52743",
    "keep_alive_path": "tcp://127.0.0.1:52743",
    "family_name": "caddy"
  },
  "mode": "prevent",
  "body_buffer_limit": 10485760,
  "response_buffer_limit": 4194304,
  "block_status_code": 403,
  "block_page_title": "Request blocked",
  "block_page_body": "Your request was blocked by the security policy.",
  "fail_open": true,
  "custom_headers": {
    "X-WAF-Engine": "openappsec"
  }
}
```

A minimal JSON config relies on defaults:

```json
{
  "handler": "openappsec",
  "engine": {
    "family_name": "caddy"
  }
}
```

An empty `transport` here resolves to the platform default (linux shm, or
the non-linux fail-open stub), and the default socket paths point at the
standard linux engine locations.

---

## 6. Request lifecycle walkthrough

All flows start the same way in `Handler.ServeHTTP`
(`internal/handler/handler.go`):

1. If the handler is unprovisioned (`acquirer == nil`): fail-closed sends 502
   (`writeUnavailable`), otherwise the request is forwarded untouched.
2. `readRequestBody` reads the entire request body with `io.ReadAll`. A read
   error logs at debug level and the request is forwarded (fail-open). A body
   larger than `body_buffer_limit` is still buffered, with a debug log.
3. The body is restored to its original bytes
   (`r.Body = newRequestBody(original)`), so compression stays intact for the
   origin.
4. `AcquireVerdict` is called with `RequestData{Start: requestStart(r)}`,
   where the REQUEST_START metadata carries protocol, method, host, listening
   port (split from `r.Host`), the unparsed URI, the client IP and port, and
   parsed host and URI, with an empty waf tag.
5. If `AcquireVerdict` returns an error: fail-closed logs at error level and
   writes 502; fail-open logs a warning ("engine unavailable, failing open")
   and forwards.
6. The verdict is switched on and, unless blocked, the request is forwarded.

### 6.1 Allow (ACCEPT)

`AcquireVerdict` returns `Kind: VerdictAccept`. The switch has no case for it,
so the request falls through to `forward`, which wraps the response in the
buffering `responseWriter`, calls the next handler, and re-emits the body
after `finalize`. For a small, identity-encoded response, `finalize`
recompresses it for gzip-accepting clients, sets `Content-Length`, writes the
header once, and streams the body.

### 6.2 Block (DROP or CUSTOM_RESPONSE)

In `prevent` mode the handler calls `writeBlock`. The status, title, and body
start from the handler config (`block_status_code` default 403,
`DefaultBlockPageTitle`, `DefaultBlockPageBody`). If the verdict carries a
custom web response (`WebResponse.Type == WebResponseCustom`), each non-zero
field overrides the configured value. The synthesized page is

```
<!DOCTYPE html>
<html>
<head><title>TITLE</title></head>
<body>
<h1>TITLE</h1>
<p>BODY</p>
</body>
</html>
```

written with `Content-Type: text/html; charset=utf-8`. `writeBlock` returns
nil so the middleware chain treats it as a completed response, not an
internal error.

In `learn` mode the same verdicts are not enforced: the handler logs an info
line ("learn mode: would block request" with method, URI, and status) and
falls through to forwarding.

### 6.3 Inject (INJECT)

`applyInjections` (`internal/handler/body.go`) walks the verdict's
injections. A header injection (`IsHeader: true`) is split on the first
colon and added to the request headers. A body injection (`IsHeader: false`)
is appended to the buffered request body. If anything changed, the modified
body is restored on `r.Body`; either way the request is forwarded. The mock
engine's `inject` scenario emits one body injection (`<mock-inject>`), so the
upstream receives the request body with those bytes appended.

### 6.4 Engine down (fail-open)

When the engine cannot be reached, `Pool.Acquire` returns the dial error and
the policy converts it to an ACCEPT verdict (`failOpenVerdict`), so the
request passes through. The handler logs the warning and forwards. When the
engine is reachable but silent (the mock `down` scenario), `await` polls
until the verdict budget expires and returns `context.DeadlineExceeded`,
which the policy also converts to ACCEPT. With defaults the budget is
`max_retries_for_verdict` (15) times `req_max_processing_ms` (3000) = 45000
ms, so a connected-but-silent engine stalls a request for up to 45 s before
it is let through. Lower `req_max_processing_ms` or `max_retries_for_verdict`
to bound that.

### 6.5 Engine down (fail-closed)

With `fail_open false` on the handler, the same failures produce a 502 "Bad
Gateway" (`writeUnavailable`: `text/plain`, `X-Content-Type-Options:
nosniff`). At boot, `Provision` also performs a reachability check when
fail-closed: it acquires the pooled connection with a
`registration_timeout_ms`-bounded context (default 100 ms, fallback 1 s) and
returns "handler: engine unavailable" if the dial fails, so a misconfigured
fail-closed deployment fails fast instead of booting into 502s.

---

## 7. Fail-open and fail-closed semantics

Fail-open is the default, matching the nginx reference attachment, which
never fails closed by default (protocol doc H.1). The switch is tri-state
everywhere: a nil `*bool` means true, and only an explicit `false` in JSON
or the Caddyfile disables it.

Two fields named `fail_open` exist and both matter:

- Engine level (`engine.fail_open`): controls whether `FailOpenPolicy`
  converts dial errors, send errors, and verdict timeouts into ACCEPT
  verdicts, or returns the underlying error to the handler.
- Handler level (`openappsec.fail_open`): controls whether the handler
  answers engine failure with 502 or forwards the request. It also gates the
  boot-time reachability check in `Provision`.

The timeouts that bound the fail-open budgets:

| Behavior | Formula | Default |
|---|---|---|
| Total verdict wait | `max_retries_for_verdict` x `req_max_processing_ms` | 15 x 3000 = 45000 ms |
| Poll sleep between non-verdict frames | `fail_open_timeout_ms` | 50 ms |
| Sleep after a REQUEST_DELAYED_VERDICT | `hold_verdict_retries` x `hold_verdict_polling_ms` | 3 x 1 = 3 ms |
| Registration / boot check bound | `registration_timeout_ms` (fallback 1 s if <= 0) | 100 ms |
| Keep-alive failure backoff | doubles from `reconnect_backoff_min_ms`, capped at `reconnect_backoff_max_ms` | 100 ms to 5000 ms |

---

## 8. Operational notes

Log level. `engine.log_level` defaults to `"info"` and is carried in the
engine config. Handler diagnostics use the Caddy zap logger at module scope:
debug lines for body read failures, over-limit bodies, blocked requests, and
decompression skips; info for learn-mode would-block; warn for fail-open
engine unavailability and invalid header injections; error for fail-closed
502s.

Keep-alive cadence. Each live connection runs a keep-alive goroutine
(`internal/app/keepalive.go`) that sends a keep-alive frame
(`[worker_id][family_name_size][family_name]`) on a dedicated raw socket,
never on the request/verdict connection. On the linux transport that
separation matters: the request path is the shared-memory ring, which would
be corrupted by foreign frames. The socket is dialed lazily on the first
tick, and a failed send drops it so the next tick redials. The default
interval (300000 ms) equals the engine's own expiry window
(`DEFAULT_KEEP_ALIVE_INTERVAL_MSEC`, protocol doc B and G.3); the engine
expires a registration not kept alive within that window, so if you see
registrations expire, lower `keep_alive_interval_ms`. A keep-alive send
failure backs off exponentially from 100 ms to 5000 ms and resets the attempt
counter on success.

Reconnect behavior. The pool dials once per registration address. On a
request, `Conn.send` retries once through `reconnect` if the first send
fails, replacing the underlying transport conn while keeping the session
allocator, so session ids stay continuous across an engine restart. The
fail-open policy hides reconnects from the handler entirely.

worker_id and workers. `worker_id` is a zero-based index; the registration
frame sends `worker_id + 1` (the nginx reference sends worker id plus one,
protocol doc G.1) and keep-alive frames send the raw uint8 value. `workers`
is the total worker count, sent in the registration frame. With a single
Caddy process, the defaults (`worker_id` 0, `workers` 1) are correct.

Concurrency. The pool is process-global and reference-counted. A Caddy
reload that re-registers the same registration address reuses the connection;
the last `Release` closes it. The linux shm dialer is the only one that uses
`verdict_signal_path` (to open the ring); for memory and socket transports
the connection already carries request and verdict traffic.

Response path. The `responseWriter` buffers the response body up to
`response_buffer_limit` and switches to passthrough (streaming unmodified)
for `text/event-stream` responses, for declared Content-Lengths above the
cap, and for bodies that overflow the cap mid-write. A fully buffered
identity response is recompressed for gzip-accepting clients and gets a
corrected Content-Length before the header is written. Response inspection
against the engine (response verdicts, `AcquireResponseVerdict`) is
implemented in the app layer but not yet called by the handler.

---

## 9. Running the mock engine

`cmd/mockengine` runs the scriptable mock engine as a standalone process for
local testing. Flags:

```
-addr       address: in-memory registry key with -transport memory (default
            "mock-engine"), or a TCP address like "tcp://127.0.0.1:0" with
            -transport socket
-scenario   allow | block | inject | flaky | down   (default "allow")
-requests   flaky only: close each connection after N request frames
            (default 1)
-transport  memory (in-process registry key) | socket (real TCP listener)
            (default "memory")
```

The engine listens on a single address and collapses the three protocol
sockets onto it: registration, comm, and keep-alive all arrive at the same
listener, and the registration reply names the engine's own address as the
verdict signal path, so the client dials the same address again for
keep-alive and request traffic. Every received frame is hex-dumped with a
one-line parsed meaning.

Scenario semantics:

| Scenario | Behavior | What you see |
|---|---|---|
| `allow` | ACCEPT every request | Requests forwarded untouched. |
| `block` | DROP with a custom web response: 403, title "Blocked by mock engine", body "This request was blocked by the mock open-appsec engine." | Handler synthesizes the block page using the verdict's overrides. |
| `inject` | INJECT a body injection carrying `<mock-inject>` | The buffered request body is appended with those bytes before forwarding. |
| `flaky` | Close each connection after `-requests` REQUEST_START frames (the nth is consumed without a reply, then the connection dies); the listener keeps accepting fresh connections | Exercises the app's one-redial-per-send reconnect path and the backoff. |
| `down` | Complete the handshake but never reply to requests | Exercises the fail-open verdict budget: requests stall up to the budget, then pass through. |

Mock engine + socket transport discovery flow:

1. Start the engine with an ephemeral port:
   `mockengine -transport socket -addr tcp://127.0.0.1:0 -scenario block`.
2. Read the logged effective address, which is the canonical
   `tcp://host:port` with the real allocated port
   ("mock engine listening on \"tcp://127.0.0.1:52743\"...").
3. Point the Caddy config at that address for both `registration_socket` and
   `keep_alive_path`, with `transport socket` and a `family_name`.
4. Run caddy, send requests, and watch both the mockengine hex dump and the
   Caddy logs.

The engine is safe for concurrent use; `SetEngineDown`/`Close` unregister
the address so a fresh engine can bind it again, and clients observe
`transport.ErrClosed`.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "connection refused" / dial errors in logs | Engine not running, or `registration_socket` points at the wrong address | Start the engine first; for the mock engine, copy the exact `tcp://host:port` it logged. |
| Requests pass through with no verdict, no block pages | Default fail-open: engine unreachable or silent, so the policy returns ACCEPT | Confirm the engine is up and the transport/address match; look for the "failing open" warning in Caddy logs. |
| Requests stall for tens of seconds, then pass through | Engine handshakes but never replies (mock `down`, or a hung engine); verdict budget is `max_retries_for_verdict` x `req_max_processing_ms` (default 45000 ms) | Lower `req_max_processing_ms` / `max_retries_for_verdict`, or fix the engine. |
| `engine shared-memory transport is only available on linux` | `transport shm` (or the empty default) on a non-linux host | Use `transport socket` with the mock engine, or run on linux for the real engine. |
| `transport "X" is not supported (supported: memory, socket, shm)` | Typo or unknown transport value | Use one of the three values, or omit it for the platform default. |
| `attachment_type "X" is not supported (supported: nginx)` | Wrong attachment type | Use `nginx`. |
| `family_name is required and must be non-empty` | `family_name` missing | Add `family_name` to the engine block. |
| Caddyfile parse error "unrecognized openappsec option" or "unrecognized engine option" | Option name misspelled, or an engine option that is JSON-only placed in the Caddyfile | Check spelling; engine options like `min_retries_for_verdict`, `hold_verdict_retries`, and `fail_open` (engine level) are JSON-only. |
| `block_status_code must be in [400, 599]` | Status out of range | Set a valid 4xx/5xx status. |
| 502 "Bad Gateway" on every request | `fail_open false` and the engine is unreachable or the handler is unprovisioned | Start the engine, or set `fail_open true`. |
| Boot fails with "handler: engine unavailable" | `fail_open false` and the engine was down during `Provision` | Start the engine before caddy, or keep fail-open. |
| Registrations expire / engine forgets the attachment | Keep-alive interval at or above the engine's 300000 ms expiry window | Lower `keep_alive_interval_ms`. |
| Mock engine rejects an address | With `-transport socket`, a bare word is not a valid TCP address | Use `tcp://host:port`; the default `-addr mock-engine` is only valid for `-transport memory`. |

---

## 11. References

- `docs/attachment-protocol.md`, the byte-level wire protocol spec. Sections:
  - A: scope and source of truth (pinned engine source tree)
  - B: constants (shared-memory paths, `DEFAULT_KEEP_ALIVE_INTERVAL_MSEC`)
  - C: enums (`AttachmentDataType`, `ServiceVerdict`, `WebResponseType`, ...)
  - D: shared-memory ring queue layout and semantics
  - E: message framing (REQUEST_START, REQUEST_BODY, RESPONSE_CODE, ...)
  - F: verdict reply structures (HttpReplyFromService, injections, web responses)
  - G: registration and communication handshake (G.1 registration, G.2 comm, G.3 keep-alive)
  - H: session lifecycle and reference config defaults (H.1)
  - J: compression pools and brotli gating
  - K: discrepancies and inferred items
- `README.md`, the user-facing companion (written by a sibling task).
- `docs/real-agent-deployment.md`, deploying against the real
  `ghcr.io/openappsec/agent` over the linux shm transport
  (`docker-compose.agent.yml`, `Caddyfile.agent`).
- `Dockerfile` and `docker-compose.yml`, deployment artifacts (written by a
  sibling task).
- `internal/e2e`, the cross-process end-to-end suite
  (`go test -tags e2e ./internal/e2e/`). It builds `cmd/mockengine` and
  `cmd/caddy` as real subprocesses and drives HTTP requests through the
  socket transport, covering the allow, block, inject, flaky, and down
  scenarios.
- `internal/mock` and `cmd/mockengine`, the scriptable mock engine used for
  local and cross-process testing.
