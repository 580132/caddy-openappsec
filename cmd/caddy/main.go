// Command caddy builds a Caddy server with the caddy-openappsec module
// compiled in. It is the local-build entry point — no xcaddy required:
//
//	go build -o bin/caddy.exe ./cmd/caddy
//
// The resulting binary registers the http.openappsec app and the
// http.handlers.openappsec handler (see imports.go) and is used by the
// cross-process E2E harness (internal/e2e).
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/yourname/caddy-openappsec"
)

func main() {
	caddycmd.Main()
}
