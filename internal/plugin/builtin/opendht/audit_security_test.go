//go:build (builtin_opendht || builtin_all) && security_audit

package opendht

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	smcrypto "github.com/tjjh89017/stunmesh-go/internal/crypto"
	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAuditOpenDHTProxyURLCredentialsReachFailureError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	// A synthetically configured proxy with HTTP Basic credentials can fail
	// during an ordinary refresh. The caller forwards this error to the app log.
	endpoint := strings.Replace(server.URL, "://", "://audit-user:audit-secret@", 1)
	store, err := NewOpenDHTPlugin(pluginapi.PluginConfig{"endpoint": endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*OpenDHTPlugin).Close()
	_, err = store.Get(context.Background(), testKey)
	if err == nil || !strings.Contains(err.Error(), "audit-secret") {
		t.Fatalf("expected synthetic URL credential in returned error, got %v", err)
	}
	t.Log("DEMONSTRATED: configured OpenDHT URL userinfo reaches a returned failure error")
}

func TestAuditNonpositiveOpenDHTTimeoutDisablesClientDeadline(t *testing.T) {
	for _, configured := range []any{"0s", "-1s", 0, -1} {
		store, err := NewOpenDHTPlugin(pluginapi.PluginConfig{
			"endpoint": "https://example.invalid", "timeout": configured,
		})
		if err != nil {
			t.Fatalf("configured timeout %v was rejected: %v", configured, err)
		}
		p := store.(*OpenDHTPlugin)
		if p.client.Timeout > 0 {
			t.Fatalf("configured timeout %v unexpectedly retained a client deadline: %v", configured, p.client.Timeout)
		}
		_ = p.Close()
	}
	t.Log("DEMONSTRATED: zero and negative OpenDHT timeout settings remove the HTTP client deadline")
}

// Passing documents a baseline availability failure: freshness is decided
// before the endpoint ciphertext is authenticated by the caller.
func TestAuditUnauthenticatedTimestampEclipsesValidRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, line(t, defaultMagic, 100, "valid-encrypted-fixture"))
		_, _ = fmt.Fprintln(w, line(t, defaultMagic, 1<<40, "not-even-hex"))
	}))
	defer server.Close()
	got, err := newTestPlugin(t, server.URL).Get(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != "not-even-hex" {
		t.Fatalf("expected unauthenticated future timestamp to eclipse genuine data, got %q", got)
	}
	t.Log("DEMONSTRATED: a public writer's unauthenticated future timestamp eclipsed a valid discovery record")
}

// The public envelope timestamp can be changed independently of its valid
// ciphertext. Decrypting before selection alone would not fix this replay.
func TestAuditPublicWriterCanReplayOldValidCiphertext(t *testing.T) {
	sender, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	encryptor := smcrypto.NewEndpoint()
	encrypt := func(content string) string {
		t.Helper()
		res, err := encryptor.Encrypt(context.Background(), &ctrl.EndpointEncryptRequest{
			PeerPublicKey: entity.PeerPublicKey(recipient.PublicKey()),
			PrivateKey:    entity.PrivateKey(sender),
			Content:       content,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Data
	}
	oldCiphertext := encrypt(`{"ipv4":"198.51.100.1:51820"}`)
	newCiphertext := encrypt(`{"ipv4":"198.51.100.2:51820"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, line(t, defaultMagic, 100, oldCiphertext))
		_, _ = fmt.Fprintln(w, line(t, defaultMagic, 101, newCiphertext))
		_, _ = fmt.Fprintln(w, line(t, defaultMagic, 1<<40, oldCiphertext))
	}))
	defer server.Close()
	got, err := newTestPlugin(t, server.URL).Get(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != oldCiphertext {
		t.Fatal("future envelope did not replay the old ciphertext")
	}
	res, err := encryptor.Decrypt(context.Background(), &ctrl.EndpointDecryptRequest{
		PeerPublicKey: entity.PeerPublicKey(sender.PublicKey()),
		PrivateKey:    entity.PrivateKey(recipient),
		Data:          got,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != `{"ipv4":"198.51.100.1:51820"}` {
		t.Fatalf("unexpected decrypted replay: %q", res.Content)
	}
	t.Log("DEMONSTRATED: public writer rewrapped valid old ciphertext with a future timestamp; Get selected and decrypted the stale endpoint instead of the newer one")
}

// The plugin relies on http.Client's default redirect policy. A configured
// proxy can point a request at an unrelated local endpoint, bypassing the
// operator's configured proxy allowlist. This uses only loopback fixtures.
func TestAuditConfiguredProxyCanRedirectIntoLocalNetwork(t *testing.T) {
	visited := make(chan string, 1)
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited <- r.URL.Path
		_, _ = fmt.Fprintln(w, line(t, defaultMagic, 1, "redirect-target"))
	}))
	defer internal.Close()
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/local-admin", http.StatusFound)
	}))
	defer proxy.Close()
	p := newTestPlugin(t, proxy.URL).(*OpenDHTPlugin)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(proxy.Certificate())
	p.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	got, err := p.Get(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != "redirect-target" || <-visited != "/local-admin" {
		t.Fatal("configured proxy redirect did not reach the unrelated loopback server")
	}
	t.Log("DEMONSTRATED: a configured HTTPS DHT proxy redirected the client to an arbitrary local HTTP URL")
}
