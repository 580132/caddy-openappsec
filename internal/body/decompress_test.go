package body

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"testing"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func readAll(t *testing.T, rc io.ReadCloser) []byte {
	t.Helper()
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	return got
}

func TestOpenRequestBody_roundtrips_gzip_when_encoding_gzip(t *testing.T) {
	payload := []byte("gzip round-trip payload: openappsec body inspection")
	rc, err := OpenRequestBody(bytes.NewReader(gzipBytes(t, payload)), "gzip")
	if err != nil {
		t.Fatalf("OpenRequestBody(gzip): %v", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, payload) {
		t.Fatalf("decoded = %q, want %q", got, payload)
	}
}

func TestOpenRequestBody_roundtrips_deflate_when_encoding_deflate(t *testing.T) {
	payload := []byte("deflate round-trip payload (zlib wrapper)")
	rc, err := OpenRequestBody(bytes.NewReader(zlibBytes(t, payload)), "deflate")
	if err != nil {
		t.Fatalf("OpenRequestBody(deflate): %v", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, payload) {
		t.Fatalf("decoded = %q, want %q", got, payload)
	}
}

func TestOpenRequestBody_brotli_is_unverified_unsupported(t *testing.T) {
	// Brotli decoding is [UNVERIFIED]: the klauspost/compress brotli package
	// is not obtainable in this environment, so "br"/"brotli" must fail
	// descriptively rather than silently corrupt data.
	for _, enc := range []string{"br", "brotli"} {
		rc, err := OpenRequestBody(bytes.NewReader([]byte("x")), enc)
		if err == nil {
			rc.Close()
			t.Fatalf("OpenRequestBody(%q): expected error, got nil", enc)
		}
		if !errors.Is(err, ErrUnsupportedEncoding) {
			t.Fatalf("OpenRequestBody(%q) error = %v, want ErrUnsupportedEncoding", enc, err)
		}
	}
}

func TestOpenRequestBody_passthrough_when_identity_or_empty(t *testing.T) {
	payload := []byte("identity payload")
	for _, enc := range []string{"", "identity"} {
		rc, err := OpenRequestBody(bytes.NewReader(payload), enc)
		if err != nil {
			t.Fatalf("OpenRequestBody(%q): %v", enc, err)
		}
		if got := readAll(t, rc); !bytes.Equal(got, payload) {
			t.Fatalf("encoding %q: got %q, want %q", enc, got, payload)
		}
	}
}

func TestOpenRequestBody_errors_on_unknown_encoding(t *testing.T) {
	rc, err := OpenRequestBody(bytes.NewReader([]byte("x")), "compress")
	if err == nil {
		rc.Close()
		t.Fatal("OpenRequestBody(compress): expected error, got nil")
	}
	if !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("error = %v, want ErrUnsupportedEncoding", err)
	}
}

func TestOpenRequestBody_is_case_and_space_insensitive(t *testing.T) {
	payload := []byte("case-insensitive encoding")
	rc, err := OpenRequestBody(bytes.NewReader(gzipBytes(t, payload)), "  GZIP ")
	if err != nil {
		t.Fatalf("OpenRequestBody(%q): %v", "  GZIP ", err)
	}
	if got := readAll(t, rc); !bytes.Equal(got, payload) {
		t.Fatalf("decoded = %q, want %q", got, payload)
	}
}

func TestOpenRequestBody_closes_underlying_decoder(t *testing.T) {
	rc, err := OpenRequestBody(bytes.NewReader(gzipBytes(t, []byte("x"))), "gzip")
	if err != nil {
		t.Fatalf("OpenRequestBody: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
