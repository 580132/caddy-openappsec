package handler

import (
	"github.com/caddyserver/caddy/v2"
)

// init registers the module so a Caddy build that imports this package picks
// the openappsec HTTP handler up automatically.
func init() {
	caddy.RegisterModule(Handler{})
}

// CaddyModule registers the handler under the http.handlers.openappsec
// namespace.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.openappsec",
		New: func() caddy.Module {
			return new(Handler)
		},
	}
}
