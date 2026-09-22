package app

import (
	"context"
	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/internal/config"
	"github.com/tjjh89017/stunmesh-go/internal/stun"
	"testing"
)

func TestServerRequiresSharedProxyTransport(t *testing.T) {
	log := zerolog.Nop()
	cfg := &config.Config{}
	dc := config.NewDeviceConfig(cfg)
	r := stun.NewResolver(cfg, dc, &log)
	if _, _, err := r.Resolve(context.Background(), "wg0", 51820, "ipv4", 0); err == nil {
		t.Fatal("raw transport fallback remains")
	}
}
