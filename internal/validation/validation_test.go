package validation

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEndpointRejectsInstructionsAndPortWrap(t *testing.T) {
	for _, endpoint := range []string{"192.0.2.1:9\npublic_key=canary", "192.0.2.1:65536", "192.0.2.1:0", "attacker.invalid:9", "[fe80::1%eth0]:9", "0.0.0.0:9", "224.0.0.1:9"} {
		if _, err := Endpoint(endpoint); err == nil {
			t.Fatalf("accepted hostile endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{"192.0.2.1:65535", "[2001:db8::1]:9"} {
		if _, err := Endpoint(endpoint); err != nil {
			t.Fatal(err)
		}
	}
}

func TestServiceRoutesCannotCoverOrdinaryInternet(t *testing.T) {
	for _, route := range []string{"0.0.0.0/0", "::/0", "128.0.0.0/1", "10.0.0.0/8", "10.1.1.1/32\npublic_key=canary", "127.0.0.1/32", "::ffff:10.0.0.1/128"} {
		if _, err := ServiceRoute(route); err == nil {
			t.Fatalf("accepted broad/invalid route %q", route)
		}
	}
	for _, route := range []string{"10.77.0.1/32", "10.77.0.0/24", "fd77::1/128"} {
		if _, err := ServiceRoute(route); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublicKeyRejectsLowOrder(t *testing.T) {
	for _, first := range []byte{0, 1} {
		key := [32]byte{first}
		if _, err := PublicKey(base64.StdEncoding.EncodeToString(key[:])); err == nil {
			t.Fatalf("accepted low-order point %d", first)
		}
	}
}

func TestJSONBoundary(t *testing.T) {
	type fixture struct {
		Value int `json:"value"`
	}
	for _, raw := range []string{`{"value":1,"value":2}`, `{"value":1,"VALUE":2}`, `{"value":null}`, `{"unknown":"SECRET_CANARY"}`, `{"value":"SECRET_CANARY"}`, `{"value":1} {}`, strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17), strings.Repeat(" ", MaxConfigBytes+1)} {
		var out fixture
		err := DecodeJSON([]byte(raw), &out)
		if err == nil {
			t.Fatal("accepted malformed configuration")
		}
		if strings.Contains(err.Error(), "SECRET_CANARY") {
			t.Fatal("secret in error")
		}
	}
	var out fixture
	if err := DecodeJSON([]byte(`{"value":7}`), &out); err != nil || out.Value != 7 {
		t.Fatalf("valid config: %v", err)
	}
}

func FuzzJSONBoundary(f *testing.F) {
	f.Add([]byte(`{"value":1}`))
	f.Add([]byte(`{"value":1,"value":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var out struct {
			Value int `json:"value"`
		}
		_ = DecodeJSON(b, &out)
	})
}
