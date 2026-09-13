//go:build (builtin_opendht || builtin_all) && security_audit

package opendht

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

type auditRoundTripper func(*http.Request) (*http.Response, error)

func (f auditRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Exercise the exact Get parser on synthetic HTTP bodies, including newline
// separation, JSON and base64. There is no network access or public DHT write.
func FuzzAuditOpenDHTGetParser(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}\n"))
	f.Add([]byte("{\"data\":\"\"}\n"))
	f.Add([]byte("{\"data\":\"eyJtYWdpYyI6InN0dW5tZXNoLXYxIiwidHMiOjEsImRhdGEiOiJmZWFkYmVlZiJ9\"}\n"))
	f.Add([]byte("{\"data\":\"!\"}\n{\"data\":\"!!!!\"}\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		p := &OpenDHTPlugin{
			endpoints: []string{"http://example.invalid"},
			magic: defaultMagic,
			client: &http.Client{Transport: auditRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(body)),
				}, nil
			})},
		}
		_, _ = p.Get(context.Background(), testKey)
	})
}
