package body

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestRecompress_gzip_roundtrip_when_accept_gzip(t *testing.T) {
	payload := []byte("recompressed gzip payload")
	encoded, encoding, err := Recompress(payload, "gzip")
	if err != nil {
		t.Fatalf("Recompress: %v", err)
	}
	if encoding != "gzip" {
		t.Fatalf("encoding = %q, want gzip", encoding)
	}

	zr, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decoded = %q, want %q", got, payload)
	}
}

func TestRecompress_identity_when_gzip_not_acceptable(t *testing.T) {
	payload := []byte("plain body")
	for _, ae := range []string{"br", "gzip;q=0", "identity"} {
		out, encoding, err := Recompress(payload, ae)
		if err != nil {
			t.Fatalf("Recompress(%q): %v", ae, err)
		}
		if encoding != "identity" {
			t.Fatalf("Accept-Encoding %q: encoding = %q, want identity", ae, encoding)
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("Accept-Encoding %q: body changed, want passthrough", ae)
		}
	}
}

func TestRecompress_identity_when_header_empty(t *testing.T) {
	payload := []byte("no accept-encoding")
	out, encoding, err := Recompress(payload, "")
	if err != nil {
		t.Fatalf("Recompress: %v", err)
	}
	if encoding != "identity" {
		t.Fatalf("encoding = %q, want identity", encoding)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("body changed, want passthrough")
	}
}

func TestRecompress_gzip_when_wildcard_accept(t *testing.T) {
	payload := []byte("wildcard accept")
	out, encoding, err := Recompress(payload, "*")
	if err != nil {
		t.Fatalf("Recompress: %v", err)
	}
	if encoding != "gzip" {
		t.Fatalf("encoding = %q, want gzip for wildcard", encoding)
	}
	if bytes.Equal(out, payload) {
		t.Fatal("body unchanged, want gzip-encoded")
	}
}

func TestRecompress_gzip_when_q_value_preferred(t *testing.T) {
	payload := []byte("q-value negotiation")
	out, encoding, err := Recompress(payload, "br;q=0.8, gzip;q=0.5")
	if err != nil {
		t.Fatalf("Recompress: %v", err)
	}
	if encoding != "gzip" {
		t.Fatalf("encoding = %q, want gzip (br not implemented, gzip acceptable)", encoding)
	}
	if bytes.Equal(out, payload) {
		t.Fatal("body unchanged, want gzip-encoded")
	}
}
