// Package caddyopenappsec is the root package of the caddy-openappsec module.
// It imports internal packages so their init-time registration runs when this
// module is compiled as part of a Caddy build.
package caddyopenappsec

import (
	_ "github.com/580132/caddy-openappsec/internal/app"
	_ "github.com/580132/caddy-openappsec/internal/handler"
)
