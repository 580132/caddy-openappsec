# caddy-openappsec

A Caddy HTTP module that runs the open-appsec Web Application Firewall engine. It is the Caddy equivalent of the open-appsec nginx attachment: Caddy asks the engine for a verdict on every request and enforces it.

## Features

- Caddyfile directive `openappsec`, plus the `http.handlers.openappsec` handler and the `http.openappsec` app module.
- Per-request engine verdicts: ACCEPT, DROP, or INJECT. Responses are buffered and re-inspected after the engine's response verdict.
- Fail-open by default. When the engine is unreachable, requests pass through; set `fail_open false` to fail closed.
- Three engine transports: `memory` (in-process, for tests), `socket` (cross-process TCP, for the mock engine and local E2E), and `shm` (linux shared-memory, for production).
- A scriptable mock engine (`cmd/mockengine`) for local E2E without a real engine.

## How it works

The module is Caddy HTTP middleware that runs before `reverse_proxy`. For each request it completes the open-appsec attachment handshake, sends the request metadata, and waits for a verdict. A DROP verdict produces a synthesized block page (or the verdict's custom web response), an INJECT verdict rewrites the request body, and an ACCEPT verdict forwards the request. The response is buffered so it can be inspected and re-emitted after the engine's response verdict.

The engine connection goes over the transport configured in the `engine` block. An empty `transport` selects the platform default: linux resolves to `shm`, every other platform resolves to an unreachable stub. The module compiles and runs anywhere; where the engine cannot be reached, the fail-open policy lets requests through. The byte-level protocol is documented in `docs/attachment-protocol.md`.

## Requirements

- Go 1.25 or newer (go.mod declares go 1.25.1).
- Caddy v2 (go.mod requires caddy v2.11.4).
- Linux is required for the `shm` production transport. The `memory` and `socket` transports run on any platform.

## Build

### With xcaddy

```
xcaddy build --with github.com/580132/caddy-openappsec
```

To build against a local checkout (what the Docker build does), use the `=replacement` form:

```
xcaddy build --with github.com/580132/caddy-openappsec=/path/to/openappsec-caddy
```

### Local wrapper

`cmd/caddy` is a Caddy main with this module compiled in. No xcaddy needed.

Windows:

```
go build -o caddy.exe ./cmd/caddy
```

macOS and Linux:

```
go build -o caddy ./cmd/caddy
```

The resulting binary registers the `http.openappsec` app and the `http.handlers.openappsec` handler.

## Configuration

### Caddyfile

The directive is `openappsec`. The `engine` block configures the connection to the engine; handler options sit at the directive level.

```
example.com {
	openappsec {
		engine {
			transport socket
			registration_socket /dev/shm/check-point/cp-nano-attachment-registration
			keep_alive_path     /dev/shm/check-point/cp-nano-attachment-registration-expiration-socket
			verdict_signal_path /dev/shm/check-point/cp-nano-http-transaction-handler
			family_name         caddy
		}
		mode                 prevent
		body_buffer_limit    10MiB
		response_buffer_limit 4MiB
		block_status_code    403
		block_page_title     "Request blocked"
		block_page_body      "Your request was blocked by the security policy."
		fail_open            true
		custom_headers {
			X-WAF-Engine openappsec
		}
	}
	reverse_proxy 127.0.0.1:8080
}
```

`transport` is one of `memory`, `socket`, `shm`. Leave it unset for the platform default (linux: `shm`, elsewhere: unreachable stub, which fails open). `family_name` is required and has no default. `attachment_type` accepts only `nginx`: the engine defines an attachment type for nginx but none for Caddy, so the module presents itself as the nginx family.

Engine block options:

| Option | Meaning |
|---|---|
| `transport` | `memory` \| `socket` \| `shm`; empty = platform default |
| `registration_socket` | Engine registration signal path |
| `keep_alive_path` | Engine keep-alive socket path |
| `verdict_signal_path` | Engine verdict signal path |
| `family_name` | Attachment family name sent in the handshake (required) |
| `worker_id` | Zero-based index of this worker |
| `workers` | Number of attachment worker processes |
| `attachment_type` | Family presented to the engine; only `nginx` is supported |
| `keep_alive_interval_ms` | Keep-alive interval, must stay below the engine's 300000 ms expiry window |
| `registration_timeout_ms` | Registration handshake timeout |
| `reconnect_backoff_min_ms` | Initial reconnect backoff |
| `reconnect_backoff_max_ms` | Reconnect backoff cap |
| `fail_open_timeout_ms` | Wait before failing open when the engine is unreachable |
| `req_max_processing_ms` | Request inspection timeout |
| `res_max_processing_ms` | Response inspection timeout |
| `log_level` | Attachment log level |

Handler options:

| Option | Default | Meaning |
|---|---|---|
| `mode` | `prevent` | `prevent` enforces verdicts; `learn` logs them and always forwards |
| `body_buffer_limit` | `10MiB` | Cap on the request body buffered for inspection |
| `response_buffer_limit` | `4MiB` | Cap on the response body buffered for inspection |
| `block_status_code` | `403` | Status returned for blocked requests |
| `block_page_title` | `Request blocked` | Title of the synthesized block page |
| `block_page_body` | `Your request was blocked by the security policy.` | Body of the synthesized block page |
| `fail_open` | `true` | Pass requests through when the engine is unavailable |
| `skip_compressed_body_inspection` | `false` | Skip decompressing compressed request bodies for inspection |
| `custom_headers` |  | Extra headers attached to block responses |

Byte sizes accept a plain integer or a suffix: `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`. All forms are binary (KiB and KB are both 1024).

### JSON

The handler registers under `http.handlers.openappsec`; the handler key is `openappsec`. Engine keys are snake_case, matching the config struct's json tags.

```json
{
	"apps": {
		"http": {
			"servers": {
				"srv0": {
					"listen": [":443"],
					"routes": [
						{
							"handle": [
								{
									"handler": "openappsec",
									"engine": {
										"transport": "socket",
										"registration_socket": "tcp://127.0.0.1:PORT",
										"keep_alive_path": "tcp://127.0.0.1:PORT",
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
							]
						}
					]
				}
			}
		}
	}
}
```

Everything you leave out is filled from the defaults, so a handler with just `"handler": "openappsec"` and an `engine` block is valid.

## Local E2E with the mock engine

`cmd/mockengine` is a scriptable mock open-appsec engine. Run it, point Caddy at it with `transport socket`, and send requests.

Terminal 1, start the mock engine:

```
go run ./cmd/mockengine -transport socket -addr tcp://127.0.0.1:0 -scenario allow
```

It prints the address it bound, with the real port when `:0` requests an ephemeral one:

```
mock engine listening on "tcp://127.0.0.1:54123" (transport socket, scenario allow)
```

Copy that `tcp://` address into a Caddyfile. Terminal 2:

```
:8080 {
	openappsec {
		engine {
			transport socket
			registration_socket tcp://127.0.0.1:54123
			keep_alive_path     tcp://127.0.0.1:54123
			family_name         caddy
		}
	}
	respond "hello from caddy"
}
```

Run the locally built Caddy (Windows: `./caddy.exe`):

```
./caddy run --config Caddyfile
```

Terminal 3:

```
curl http://127.0.0.1:8080/
```

The mock engine hex-dumps every frame it receives with a one-line meaning.

Scenarios:

| Scenario | Behavior |
|---|---|
| `allow` | ACCEPT every request. `curl` returns the upstream response. |
| `block` | DROP every request with a custom 403 web response. `curl` shows the mock's block page. |
| `inject` | INJECT a `<mock-inject>` tag into every response body. |
| `flaky` | Close each connection after N request frames (`-requests`, default 1), exercising the reconnect/backoff path. |
| `down` | Complete the handshake but never reply to requests, exercising the fail-open timeout budget. |

Restart the mock engine with `-scenario block`, `-scenario inject`, and so on to exercise the others. The mock engine's default `memory` transport is for in-process tests; cross-process E2E always uses `socket`.

## Docker

The repo ships a `Dockerfile` and a `docker-compose.yml` with a `caddy` service and a `mockengine` service. Build and start both:

```
docker compose up --build
```

Then send a request to the caddy service:

```
curl http://localhost:8080/
```

## Docs

- `docs/integration.md` — deploying with the real open-appsec engine.
- `docs/attachment-protocol.md` — the byte-level wire protocol contract this module implements.

## License

Apache License 2.0. Copyright 2026 The caddy-openappsec Authors. See LICENSE.
