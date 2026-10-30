package edge

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReleaseImageRequiresMatchingChecksum(t *testing.T) {
	const payload = "isolated image archive fixture"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
	for _, tc := range []struct {
		name, checksum, body string
		wantLoad             bool
	}{
		{"valid", digest, payload, true},
		{"corrupt", digest, payload + " changed", false},
		{"no checksum", "", payload, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "docker-calls")
			t.Setenv("WEB_EDGE_TEST_LOG", calls)
			t.Setenv("PATH", dir)
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$WEB_EDGE_TEST_LOG\"\n"), 0755); err != nil {
				t.Fatal(err)
			}
			old := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = old })
			name := "web-edge-image-linux-" + runtime.GOARCH + ".tar.gz"
			http.DefaultTransport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme != "https" || r.URL.Host != "github.com" {
					t.Fatal("unexpected download origin", r.URL)
				}
				body := tc.body
				if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
					body = tc.checksum + "  " + name + "\n"
				} else if !strings.HasSuffix(r.URL.Path, "/"+name) {
					t.Fatal("unexpected asset", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			err := loadReleaseImage(DefaultImage)
			if (err == nil) != tc.wantLoad {
				t.Fatalf("unexpected result: %v", err)
			}
			b, _ := os.ReadFile(calls)
			loaded := strings.Contains(string(b), "load -i ")
			if loaded != tc.wantLoad {
				t.Fatalf("unverified archive reached docker load: %q", b)
			}
		})
	}
}
