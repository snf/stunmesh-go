package wg

import (
	"context"
	"net"
	"os/exec"

	"github.com/tjjh89017/stunmesh-go/internal/validation"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgctrlBackend is the subset of *wgctrl.Client that ctrlClient uses,
// extracted as a test seam so Device/UpdatePeerEndpoint can be exercised
// with a fake instead of a real WireGuard device.
type wgctrlBackend interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Close() error
}

type ctrlClient struct {
	c      wgctrlBackend
	runner Runner
}

func New() (Client, error) {
	if _, err := exec.LookPath("wg"); err != nil {
		return nil, err
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &ctrlClient{c: c, runner: defaultRunner}, nil
}

// Device reads only public metadata through the standard WireGuard tool.
func (cc *ctrlClient) Device(ctx context.Context, name string) (*DeviceInfo, error) {
	return publicInfo(ctx, name, cc.runner)
}

// UpdatePeerEndpoint ignores ctx: wgctrl has no context-aware API.
func (cc *ctrlClient) UpdatePeerEndpoint(ctx context.Context, u PeerEndpointUpdate) error {
	ep, err := validation.HostPort(u.Host, u.Port)
	if err != nil {
		return err
	}
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:  wgtypes.Key(u.PublicKey),
				UpdateOnly: UpdateOnly,
				Endpoint: &net.UDPAddr{
					IP:   net.IP(ep.Addr().AsSlice()),
					Port: int(ep.Port()),
				},
			},
		},
	}
	return elevationHint(cc.c.ConfigureDevice(u.DeviceName, cfg))
}

func (cc *ctrlClient) Close() error {
	return cc.c.Close()
}
