package app

import (
	"context"
	"time"

	"github.com/580132/caddy-openappsec/internal/config"
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is the Caddy application module that runs the open-appsec attachment: it
// maintains the engine connection pool and exposes the fail-open verdict
// surface the HTTP handler wave calls. Provision is cheap and side-effect free
// (Caddy convention); Start lazily dials the engine, and Stop releases the
// pooled connection.
type App struct {
	// Config is the engine configuration, filled from Caddy JSON by the
	// caddy app module loader.
	Config config.EngineConfig

	pool   *Pool
	policy VerdictAcquirer
}

// CaddyModule registers the app under the http.openappsec namespace.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.openappsec",
		New: func() caddy.Module {
			return new(App)
		},
	}
}

// Provision builds the shared engine pool and the fail-open policy. It has no
// side effects: the engine is not contacted until Start. A pool set before
// Provision (test seam) is respected; production always uses the process-global
// pool so a Caddy reload re-registering the same engine address reuses the
// connection.
func (a *App) Provision(ctx caddy.Context) error {
	if a.pool == nil {
		a.pool = GlobalPool(a.Config, NewDialer(a.Config))
	}
	a.policy = NewFailOpenPolicy(a.Config, a.pool)
	return nil
}

// Start lazily dials the engine so the attachment is registered before the
// first request. If the engine is unreachable the server still boots: the
// fail-open policy degrades requests to allow-through unless FailOpen is
// explicitly disabled.
func (a *App) Start() error {
	timeout := time.Duration(a.Config.RegistrationTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := a.pool.Acquire(ctx, a.Config.RegistrationSocket)
	if err != nil && !failOpenEnabled(a.Config) {
		return err
	}
	return nil
}

// Stop releases the pooled engine connection. Other users of the same engine
// address keep their references; the last release tears the connection down.
func (a *App) Stop() error {
	a.pool.Release(a.Config.RegistrationSocket)
	return nil
}

// Cleanup releases any pooled connection on configuration teardown.
func (a *App) Cleanup() error {
	return a.Stop()
}
