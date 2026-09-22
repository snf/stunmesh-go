package entity_test

import (
	"testing"

	"github.com/tjjh89017/stunmesh-go/internal/entity"
)

func TestNewDevice(t *testing.T) {
	name := entity.DeviceId("wg0")
	listenPort := 51820
	protocol := "ipv4"
	firewallMark := 0xca6c

	device := entity.NewDevice(name, listenPort, protocol, firewallMark)

	if device == nil {
		t.Fatal("Expected device to be created")
	}

	if device.Name() != name {
		t.Errorf("Expected name %s, got %s", name, device.Name())
	}

	if device.ListenPort() != listenPort {
		t.Errorf("Expected listen port %d, got %d", listenPort, device.ListenPort())
	}

	if device.Protocol() != protocol {
		t.Errorf("Expected protocol %s, got %s", protocol, device.Protocol())
	}

	if device.FirewallMark() != firewallMark {
		t.Errorf("Expected firewall mark %#x, got %#x", firewallMark, device.FirewallMark())
	}

}

func TestDevice_Name(t *testing.T) {
	tests := []struct {
		name       string
		deviceName entity.DeviceId
	}{
		{"simple name", "wg0"},
		{"multiple digits", "wg10"},
		{"uppercase", "WG0"},
		{"with dash", "wg-test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := entity.NewDevice(tt.deviceName, 51820, "ipv4", 0)

			if device.Name() != tt.deviceName {
				t.Errorf("Expected name %s, got %s", tt.deviceName, device.Name())
			}
		})
	}
}

func TestDevice_ListenPort(t *testing.T) {
	tests := []struct {
		name       string
		listenPort int
	}{
		{"standard port", 51820},
		{"custom port", 12345},
		{"high port", 65535},
		{"low port", 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := entity.NewDevice("wg0", tt.listenPort, "ipv4", 0)

			if device.ListenPort() != tt.listenPort {
				t.Errorf("Expected listen port %d, got %d", tt.listenPort, device.ListenPort())
			}
		})
	}
}

func TestDevice_Protocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
	}{
		{"ipv4", "ipv4"},
		{"ipv6", "ipv6"},
		{"dualstack", "dualstack"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := entity.NewDevice("wg0", 51820, tt.protocol, 0)

			if device.Protocol() != tt.protocol {
				t.Errorf("Expected protocol %s, got %s", tt.protocol, device.Protocol())
			}
		})
	}
}

func TestErrDeviceNotFound(t *testing.T) {
	err := entity.ErrDeviceNotFound

	if err == nil {
		t.Fatal("ErrDeviceNotFound should not be nil")
	}

	if err.Error() == "" {
		t.Error("ErrDeviceNotFound should have non-empty error message")
	}

	expectedMsg := "device not found"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}
