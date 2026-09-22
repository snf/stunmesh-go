package entity

import (
	"errors"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
)

var (
	ErrDeviceNotFound = errors.New("device not found")
)

type DeviceId string

type Device struct {
	name         DeviceId
	listenPort   int
	protocol     string
	firewallMark int
}

// NewDevice holds only public interface metadata needed by discovery.
func NewDevice(name DeviceId, listenPort int, protocol string, firewallMark int) *Device {
	return &Device{
		name:         name,
		listenPort:   listenPort,
		protocol:     protocol,
		firewallMark: firewallMark,
	}
}

func (d *Device) Name() DeviceId {
	return d.name
}

func (d *Device) ListenPort() int {
	return d.listenPort
}

func (d *Device) Protocol() string {
	return d.protocol
}

func (d *Device) FirewallMark() int {
	return d.firewallMark
}

// DeviceStatus records the local host's last STUN discovery result for a
// device, so EstablishController can tell which endpoint address families
// the local host itself can actually reach.
type DeviceStatus = discovery.LocalStatus
