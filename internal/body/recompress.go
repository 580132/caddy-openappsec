package body

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strconv"
	"strings"
)

// Recompress re-encodes body according to the client's Accept-Encoding header
// and returns the encoded bytes together with the Content-Encoding value the
// caller must set on the response.
//
// Negotiation is gzip-preferred with identity fallback: gzip is used when the
// header accepts it (explicitly with q > 0, or via a wildcard "*" when gzip
// is not explicitly listed); otherwise the body is returned unchanged with
// encoding "identity". Brotli recompression is [UNVERIFIED] and never
// selected; a client that accepts only "br" receives identity, which every
// HTTP client must accept.
func Recompress(body []byte, acceptEncoding string) ([]byte, string, error) {
	if !acceptsGzip(acceptEncoding) {
		return body, "identity", nil
	}

	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		// BestSpeed is a valid level; this cannot fail.
		return nil, "", fmt.Errorf("body: gzip writer: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return nil, "", fmt.Errorf("body: gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("body: gzip close: %w", err)
	}
	return buf.Bytes(), "gzip", nil
}

// acceptsGzip reports whether the Accept-Encoding header permits gzip,
// following RFC 9110 §12.5.3: an explicitly listed encoding with q > 0 is
// acceptable; a wildcard "*" with q > 0 makes any unlisted encoding
// acceptable; an explicit listing overrides the wildcard for that encoding.
func acceptsGzip(header string) bool {
	if strings.TrimSpace(header) == "" {
		return false
	}
	gzipQ := -1.0 // not explicitly listed
	wildcardQ := 0.0
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(item, ";")
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		q := 1.0
		for _, param := range parts[1:] {
			kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
			if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "q") {
				if v, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil {
					q = v
				}
			}
		}
		switch name {
		case "gzip":
			gzipQ = q
		case "*":
			wildcardQ = q
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return wildcardQ > 0
}
