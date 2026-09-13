//go:build linux && security_audit

package stun

import (
	"context"
	"net"
	"testing"
	"time"

	stunlib "github.com/pion/stun/v3"
)

// A STUN-shaped response from an unconfigured source is accepted even when no
// request was sent. The production Connect path likewise sends a request but
// does not compare the response transaction ID or source to it. This is a
// local network-namespace reproduction, never a packet to a public service.
func TestAuditUnsolicitedSTUNControlsDiscoveredEndpoint(t *testing.T) {
	victim, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	port := uint16(victim.LocalAddr().(*net.UDPAddr).Port)

	monitor, err := New(context.Background(), "", port, "ipv4", 0, nil, false)
	if err != nil {
		t.Skipf("isolated environment cannot open the production raw STUN socket: %v", err)
	}
	defer monitor.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	monitor.Start(ctx)

	forged, err := stunlib.Build(stunlib.TransactionID, stunlib.BindingSuccess,
		&stunlib.XORMappedAddress{IP: net.IPv4(198, 51, 100, 77), Port: 54321})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	go func() {
		for range 20 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, _ = sender.WriteToUDP(forged.Raw, victim.LocalAddr().(*net.UDPAddr))
			time.Sleep(25 * time.Millisecond)
		}
	}()
	reply, err := monitor.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mapped := Parse(context.Background(), reply)
	if mapped == nil || !mapped.IP.Equal(net.IPv4(198, 51, 100, 77)) || mapped.Port != 54321 {
		t.Fatalf("forged mapped address not returned: %+v", mapped)
	}
	t.Log("DEMONSTRATED: raw STUN reader accepted an unsolicited response from 127.0.0.2 and extracted the attacker-chosen endpoint")
}
