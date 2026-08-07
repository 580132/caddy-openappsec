package handler

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/yourname/caddy-openappsec/internal/config"
)

// init registers the Caddyfile directive and its default position: the
// openappsec middleware must run after request_body buffering but before
// reverse_proxy forwards the request upstream.
func init() {
	httpcaddyfile.RegisterHandlerDirective("openappsec", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("openappsec", httpcaddyfile.Before, "reverse_proxy")
}

// parseCaddyfile unmarshals the openappsec directive from a Caddyfile block.
//
//	openappsec {
//	    engine {
//	        registration_socket /dev/shm/check-point/cp-nano-attachment-registration
//	        keep_alive_path     /dev/shm/check-point/cp-nano-attachment-registration-expiration-socket
//	        verdict_signal_path /dev/shm/check-point/cp-nano-http-transaction-handler
//	        # transport: memory (in-process tests), socket (cross-process TCP mock engine),
//	        # shm (linux production default); empty means the platform default.
//	        transport socket
//	        family_name         caddy
//	    }
//	    mode prevent
//	    body_buffer_limit     10MiB
//	    response_buffer_limit 4MiB
//	    block_status_code     403
//	    block_page_title      "Request blocked"
//	    block_page_body       "Your request was blocked by the security policy."
//	    fail_open             true
//	    custom_headers {
//	        X-WAF-Engine openappsec
//	    }
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hnd := new(Handler)
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "engine":
				if err := parseEngineBlock(h, &hnd.Engine); err != nil {
					return nil, err
				}
			case "mode":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				hnd.Mode = config.Mode(h.Val())
			case "body_buffer_limit":
				n, err := sizeArg(h)
				if err != nil {
					return nil, err
				}
				hnd.BodyBufferLimit = n
			case "response_buffer_limit":
				n, err := sizeArg(h)
				if err != nil {
					return nil, err
				}
				hnd.ResponseBufferLimit = n
			case "block_status_code":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				code, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.Errf("block_status_code: invalid integer %q", h.Val())
				}
				hnd.BlockStatusCode = code
			case "block_page_title":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				hnd.BlockPageTitle = h.Val()
			case "block_page_body":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				hnd.BlockPageBody = h.Val()
			case "fail_open":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				b, err := strconv.ParseBool(h.Val())
				if err != nil {
					return nil, h.Errf("fail_open: invalid boolean %q", h.Val())
				}
				hnd.FailOpen = &b
			case "skip_compressed_body_inspection":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				b, err := strconv.ParseBool(h.Val())
				if err != nil {
					return nil, h.Errf("skip_compressed_body_inspection: invalid boolean %q", h.Val())
				}
				hnd.SkipCompressedBodyInspection = b
			case "custom_headers":
				if hnd.CustomHeaders == nil {
					hnd.CustomHeaders = make(map[string]string)
				}
				for h.NextBlock(1) {
					key := h.Val()
					if !h.NextArg() {
						return nil, h.ArgErr()
					}
					hnd.CustomHeaders[key] = h.Val()
				}
			default:
				return nil, h.Errf("unrecognized openappsec option %q", h.Val())
			}
		}
	}
	hnd.SetDefaults()
	return hnd, nil
}

// parseEngineBlock unmarshals the engine sub-configuration.
func parseEngineBlock(h httpcaddyfile.Helper, cfg *config.EngineConfig) error {
	for h.NextBlock(1) {
		switch h.Val() {
		case "registration_socket":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.RegistrationSocket = h.Val()
		case "keep_alive_path":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.KeepAlivePath = h.Val()
		case "verdict_signal_path":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.VerdictSignalPath = h.Val()
		case "transport":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.Transport = h.Val()
		case "family_name":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.FamilyName = h.Val()
		case "worker_id":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("worker_id: invalid integer %q", h.Val())
			}
			cfg.WorkerID = n
		case "workers":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("workers: invalid integer %q", h.Val())
			}
			cfg.Workers = n
		case "attachment_type":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.AttachmentType = h.Val()
		case "keep_alive_interval_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("keep_alive_interval_ms: invalid integer %q", h.Val())
			}
			cfg.KeepAliveIntervalMs = n
		case "registration_timeout_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("registration_timeout_ms: invalid integer %q", h.Val())
			}
			cfg.RegistrationTimeoutMs = n
		case "reconnect_backoff_min_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("reconnect_backoff_min_ms: invalid integer %q", h.Val())
			}
			cfg.ReconnectBackoffMinMs = n
		case "reconnect_backoff_max_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("reconnect_backoff_max_ms: invalid integer %q", h.Val())
			}
			cfg.ReconnectBackoffMaxMs = n
		case "fail_open_timeout_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("fail_open_timeout_ms: invalid integer %q", h.Val())
			}
			cfg.FailOpenTimeoutMs = n
		case "req_max_processing_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("req_max_processing_ms: invalid integer %q", h.Val())
			}
			cfg.ReqMaxProcessingMs = n
		case "res_max_processing_ms":
			if !h.NextArg() {
				return h.ArgErr()
			}
			n, err := strconv.Atoi(h.Val())
			if err != nil {
				return h.Errf("res_max_processing_ms: invalid integer %q", h.Val())
			}
			cfg.ResMaxProcessingMs = n
		case "log_level":
			if !h.NextArg() {
				return h.ArgErr()
			}
			cfg.LogLevel = h.Val()
		default:
			return h.Errf("unrecognized engine option %q", h.Val())
		}
	}
	return nil
}

// sizeArg consumes a single size argument (plain integer bytes or a size
// with a binary suffix like "10MiB") and returns its value in bytes.
func sizeArg(h httpcaddyfile.Helper) (int, error) {
	if !h.NextArg() {
		return 0, h.ArgErr()
	}
	n, err := parseSize(h.Val())
	if err != nil {
		return 0, h.Errf("invalid size %q: %v", h.Val(), err)
	}
	return n, nil
}

// parseSize parses a byte size with an optional binary suffix (KB, MB, GB,
// KiB, MiB, GiB), case-insensitively. A bare number is bytes.
func parseSize(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	mult := 1
	lower := strings.ToLower(s)
	for _, suf := range []struct {
		suffix string
		factor int
	}{
		{"gib", 1 << 30},
		{"gb", 1 << 30},
		{"mib", 1 << 20},
		{"mb", 1 << 20},
		{"kib", 1 << 10},
		{"kb", 1 << 10},
		{"b", 1},
	} {
		if strings.HasSuffix(lower, suf.suffix) {
			mult = suf.factor
			s = s[:len(s)-len(suf.suffix)]
			break
		}
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > int64(^uint(0)>>1)/int64(mult) {
		return 0, strconv.ErrRange
	}
	return int(n) * mult, nil
}
