package opendht

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "3061b8fcbdb6972059518f1adc3590dca6a5f352"
const testRecord = `{"version":2,"ipv4":"198.51.100.1:51820"}`

func line(record string) string {
	e, _ := json.Marshal(envelope{Magic: discovery.Namespace, Data: record})
	v, _ := json.Marshal(value{Data: base64.StdEncoding.EncodeToString(e)})
	return string(v) + "\n"
}
func newTestPlugin(t *testing.T, s *httptest.Server) *OpenDHTPlugin {
	t.Helper()
	store, err := NewOpenDHTPlugin(pluginapi.PluginConfig{"name": "opendht", "endpoint": s.URL})
	if err != nil {
		t.Fatal(err)
	}
	p := store.(*OpenDHTPlugin)
	p.client.Transport = s.Client().Transport
	t.Cleanup(func() { p.Close() })
	return p
}
func TestHintRoundTrip(t *testing.T) {
	var saved string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/key/"+testKey {
			t.Error("wrong lookup path")
		}
		if r.Method == http.MethodPost {
			var v value
			if json.NewDecoder(r.Body).Decode(&v) != nil {
				t.Error("bad publication")
			}
			b, _ := json.Marshal(v)
			saved = string(b)
			return
		}
		fmt.Fprintln(w, saved)
	}))
	defer s.Close()
	p := newTestPlugin(t, s)
	if err := p.Set(context.Background(), testKey, testRecord); err != nil {
		t.Fatal(err)
	}
	got, err := p.Get(context.Background(), testKey)
	if err != nil || len(got) != 1 || got[0] != testRecord {
		t.Fatal("roundtrip failed", err)
	}
	for _, key := range []string{"../path", strings.Repeat("0", 41), strings.Repeat("A", 40)} {
		if _, err := p.Get(context.Background(), key); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
}
func TestFallbackAlsoForInvalidSuccess(t *testing.T) {
	for _, bad := range []string{"", `{}`, line(`{"version":1,"ipv4":"198.51.100.1:9"}`), strings.Repeat("x", MaxResponseBytes+1)} {
		t.Run(fmt.Sprint(len(bad)), func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, line(testRecord)) }))
			defer s.Close()
			first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, bad) }))
			defer first.Close()
			p := newTestPlugin(t, s)
			p.endpoints = []string{first.URL, s.URL}
			got, err := p.Get(context.Background(), testKey)
			if err != nil || len(got) != 1 || calls.Load() != 1 {
				t.Fatal("invalid first proxy prevented fallback", err)
			}
		})
	}
}
func TestLimitsAndNoTimestampAuthority(t *testing.T) {
	if len(candidates([]byte(strings.Repeat(line(testRecord), MaxRecords+1)))) != 0 {
		t.Fatal("record count bound missing")
	}
	data := ""
	for i := 1; i <= 8; i++ {
		data += line(fmt.Sprintf(`{"version":2,"ipv4":"198.51.100.%d:9"}`, i))
	}
	if len(candidates([]byte(data))) != MaxCandidates {
		t.Fatal("candidate bound missing")
	}
	e, _ := json.Marshal(map[string]any{"magic": discovery.Namespace, "data": testRecord, "ts": int64(9223372036854775807)})
	v, _ := json.Marshal(value{Data: base64.StdEncoding.EncodeToString(e)})
	if len(candidates(v)) != 0 {
		t.Fatal("legacy timestamp accepted")
	}
	for _, record := range []string{`{"version":2,"ipv4":"198.51.100.1:9","private_key":"x"}`, `{"version":2,"ipv4":"198.51.100.1:9","ipv4":"198.51.100.2:9"}`} {
		if len(candidates([]byte(line(record)))) != 0 {
			t.Fatal("bad record accepted")
		}
	}
}
func TestRedirectAndDecompressedLimit(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer target.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer s.Close()
	p := newTestPlugin(t, s)
	if _, err := p.Get(context.Background(), testKey); err == nil || reached.Load() != 0 {
		t.Fatal("redirect followed")
	}
	zipped := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		z.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
		z.Close()
	}))
	defer zipped.Close()
	if _, err := newTestPlugin(t, zipped).Get(context.Background(), testKey); err == nil {
		t.Fatal("decompression bound missing")
	}
}
func TestHTTPSAndTimeoutPolicy(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://u:p@example.com", "https://example.com/path", "https://example.com/?x=1", "https://example.com/#x", "https://example.com:70000"} {
		if _, err := NewOpenDHTPlugin(pluginapi.PluginConfig{"name": "opendht", "endpoint": endpoint}); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	for _, timeout := range []string{"0s", "-1s", "21s", "bad"} {
		if _, err := NewOpenDHTPlugin(pluginapi.PluginConfig{"name": "opendht", "endpoint": "https://example.com", "timeout": timeout}); err == nil {
			t.Fatal("invalid timeout accepted")
		}
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	p := newTestPlugin(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := p.Get(ctx, testKey); err == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation ignored")
	}
}
func FuzzCandidates(f *testing.F) {
	f.Add([]byte(line(testRecord)))
	f.Add([]byte(`{"data":"!!"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		got := candidates(b)
		if len(got) > MaxCandidates {
			t.Fatal("unbounded candidates")
		}
		for _, v := range got {
			if _, err := discovery.Decode(v); err != nil {
				t.Fatal("unvalidated candidate")
			}
		}
	})
}
