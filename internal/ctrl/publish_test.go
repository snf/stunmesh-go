package ctrl_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	"github.com/tjjh89017/stunmesh-go/internal/plugin/dialer"
	"github.com/tjjh89017/stunmesh-go/internal/repo"
	"github.com/tjjh89017/stunmesh-go/internal/wg"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
)

type hintStore struct {
	records []string
	writes  []string
	keys    []string
	err     error
	escape  dialer.Escape
}

func (s *hintStore) Get(ctx context.Context, key string) ([]string, error) {
	s.escape = dialer.EscapeFrom(ctx)
	return s.records, s.err
}
func (s *hintStore) Set(ctx context.Context, key, value string) error {
	s.keys = append(s.keys, key)
	s.writes = append(s.writes, value)
	s.escape = dialer.EscapeFrom(ctx)
	return s.err
}

type hintProvider struct{ s *hintStore }

func (p hintProvider) GetPlugin(name string) (pluginapi.Store, error) {
	if name != "dht" {
		return nil, errors.New("unknown store")
	}
	return p.s, nil
}

type resolver struct {
	mark int
	fail bool
}

func (r *resolver) Resolve(ctx context.Context, name string, port uint16, protocol string, mark int) (string, int, error) {
	r.mark = mark
	if r.fail {
		return "", 0, errors.New("offline")
	}
	return "198.51.100.1", 51820, nil
}

type endpointClient struct {
	updates []wg.PeerEndpointUpdate
	err     error
}

func (c *endpointClient) Device(context.Context, string) (*wg.DeviceInfo, error) { return nil, c.err }
func (c *endpointClient) UpdatePeerEndpoint(ctx context.Context, u wg.PeerEndpointUpdate) error {
	c.updates = append(c.updates, u)
	return c.err
}
func setupHints() (*repo.Devices, *repo.Peers, *entity.Peer) {
	d := repo.NewDevices()
	p := repo.NewPeers(nil)
	ctx := context.Background()
	d.Save(ctx, entity.NewDevice("wg0", 51820, "ipv4", 0xca6c))
	key := [32]byte{9}
	peer := entity.NewPeer(entity.NewPeerId([]byte{8}, key[:]), "wg0", key, "dht", "ipv4", entity.PeerPingConfig{})
	p.Save(ctx, peer)
	return d, p, peer
}
func TestPublishRenewsUnchangedHintAndRetainsSocketEscape(t *testing.T) {
	d, p, peer := setupHints()
	s := &hintStore{}
	r := &resolver{}
	log := zerolog.Nop()
	c := ctrl.NewPublishController(d, p, hintProvider{s}, r, nil, &log)
	c.Execute(context.Background())
	c.Execute(context.Background())
	if len(s.writes) != 2 || s.writes[0] != s.writes[1] {
		t.Fatal("unchanged hints must still renew TTL")
	}
	record, err := discovery.Decode(s.writes[0])
	if err != nil || record.IPv4 != "198.51.100.1:51820" {
		t.Fatal("invalid public hint", err)
	}
	if s.keys[0] != peer.LocalId() || r.mark != 0xca6c {
		t.Fatal("wrong publication identity or socket mark")
	}
	r.fail = true
	c.Execute(context.Background())
	if len(s.writes) != 2 {
		t.Fatal("published after STUN failure")
	}
}
func TestPublishStoreFailureDoesNotSuppressNextRenewal(t *testing.T) {
	d, p, _ := setupHints()
	s := &hintStore{err: errors.New("offline")}
	log := zerolog.Nop()
	c := ctrl.NewPublishController(d, p, hintProvider{s}, &resolver{}, nil, &log)
	c.Execute(context.Background())
	s.err = nil
	c.Execute(context.Background())
	if len(s.writes) != 2 {
		t.Fatal("renewal lost")
	}
}
