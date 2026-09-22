package ctrl_test

import (
	"context"
	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/internal/wg"
	"testing"
	"time"
)

func TestEstablishHintsCannotChangeTrustedPeerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, record string
		valid        bool
	}{
		{"valid", `{"version":2,"ipv4":"198.51.100.2:51820"}`, true},
		{"legacy", `{"ipv4":"198.51.100.2:51820"}`, false},
		{"private", `{"version":2,"ipv4":"192.168.0.1:80"}`, false},
		{"loopback", `{"version":2,"ipv4":"127.0.0.1:80"}`, false},
		{"inject", `{"version":2,"ipv4":"198.51.100.2:51820\nreplace_peers=true"}`, false},
		{"authorize", `{"version":2,"ipv4":"198.51.100.2:51820","public_key":"attacker"}`, false},
		{"empty", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, p, peer := setupHints()
			s := &hintStore{records: []string{tc.record}}
			client := &endpointClient{}
			log := zerolog.Nop()
			c := ctrl.NewEstablishController(client, d, p, hintProvider{s}, nil, &log)
			c.Execute(context.Background(), peer.Id())
			if !tc.valid {
				if len(client.updates) != 0 {
					t.Fatal("untrusted data changed WG")
				}
				return
			}
			if len(client.updates) != 1 {
				t.Fatal("valid hint not applied")
			}
			u := client.updates[0]
			if u.PublicKey != peer.PublicKey() || u.DeviceName != "wg0" || u.Host != "198.51.100.2" || u.Port != 51820 {
				t.Fatal("hint changed trusted peer identity")
			}
		})
	}
}
func TestEstablishEmptyResponseIsSafe(t *testing.T) {
	d, p, peer := setupHints()
	s := &hintStore{}
	log := zerolog.Nop()
	c := ctrl.NewEstablishController(&endpointClient{}, d, p, hintProvider{s}, nil, &log)
	c.Execute(context.Background(), peer.Id())
}

type healthyClient struct{ endpointClient }

func (c *healthyClient) PeerHealth(context.Context, string, wg.Key) (discovery.Health, error) {
	return discovery.Health{Endpoint: "198.51.100.3:9", Handshake: time.Now().Add(-time.Minute)}, nil
}
func TestForgedHintDoesNotReplaceAuthenticatedEndpoint(t *testing.T) {
	d, p, peer := setupHints()
	s := &hintStore{records: []string{`{"version":2,"ipv4":"198.51.100.2:9"}`}}
	log := zerolog.Nop()
	client := &healthyClient{}
	c := ctrl.NewEstablishController(client, d, p, hintProvider{s}, nil, &log)
	c.Execute(context.Background(), peer.Id())
	if len(client.updates) != 0 {
		t.Fatal("working WG endpoint replaced by an unauthenticated hint")
	}
}
