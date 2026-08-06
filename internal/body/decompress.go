package body

import (
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrUnsupportedEncoding is returned by OpenRequestBody when the declared
// Content-Encoding cannot be decoded. The handler decides how to fall back;
// OpenRequestBody never silently produces corrupt data.
//
// Brotli ("br"/"brotli") is [UNVERIFIED]: Go's standard library has no brotli
// decoder, and the brotli package of the only in-graph brotli-capable module
// (github.com/klauspost/compress) is not obtainable in this environment, so
// this build reports brotli as unsupported rather than misdecoding it. The
// nginx reference gates brotli inspection behind is_brotli_inspection_enabled
// (default off) for the same practical reason.
var ErrUnsupportedEncoding = errors.New("body: unsupported Content-Encoding")

// OpenRequestBody wraps r with the decoder matching the declared
// Content-Encoding. It returns an io.ReadCloser whose Close releases decoder
// resources. Supported encodings:
//
//   - "" or "identity": passthrough (no decoder)
//   - "gzip": compress/gzip
//   - "deflate": compress/zlib (the zlib wrapper is what HTTP servers
//     commonly emit for Content-Encoding: deflate)
//
// The encoding is matched case-insensitively with surrounding whitespace
// trimmed. Any other value, including "br"/"brotli" in this build, returns
// an error wrapping ErrUnsupportedEncoding; the caller must not fall back to
// reading the stream undecoded, because that would submit compressed bytes
// to the inspection engine as if they were plain text.
func OpenRequestBody(r io.Reader, encoding string) (io.ReadCloser, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return io.NopCloser(r), nil
	case "gzip":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("body: gzip: %w", err)
		}
		return zr, nil
	case "deflate":
		zr, err := zlib.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("body: deflate: %w", err)
		}
		return zr, nil
	case "br", "brotli":
		return nil, fmt.Errorf(
			"%w: brotli decoding is unavailable in this build [UNVERIFIED]",
			ErrUnsupportedEncoding,
		)
	default:
		return nil, fmt.Errorf(
			"%w: %q (supported: gzip, deflate, identity)",
			ErrUnsupportedEncoding, encoding,
		)
	}
}
