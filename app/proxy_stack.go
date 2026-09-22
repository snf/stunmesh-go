package app

import (
	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/internal/config"
	"github.com/tjjh89017/stunmesh-go/internal/stun"
	"github.com/tjjh89017/stunmesh-go/internal/wg"
	"github.com/tjjh89017/stunmesh-go/internal/wgproxy"
)

type proxyStack struct {
	Client   wg.Client
	Resolver *stun.Resolver
}

func newProxyStack(cfg *config.Config, dc *config.DeviceConfig, log *zerolog.Logger) (*proxyStack, func(), error) {
	manager := wgproxy.NewManager(log)
	inner, err := wg.New()
	if err != nil {
		return nil, nil, err
	}
	client := wg.NewProxyClient(inner, manager, dc, log)
	factory := stun.NewProxyLookupFactory(func(name string) (stun.StunTransport, error) { return manager.Get(name) }, log)
	resolver := stun.NewResolverWithFactory(cfg, dc, log, factory)
	return &proxyStack{Client: client, Resolver: resolver}, func() { client.Close() }, nil
}
