//go:build linux && security_audit

package stun

import (
	"context"
	"errors"
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

// The Linux raw-socket listener delivers only one packet and then returns.
// A syntactically valid but unusable reply from the first configured STUN
// server therefore consumes the listener, leaving the second server's valid
// reply unread despite the resolver's documented fallback loop.
func TestAuditRawSTUNFallbackCannotReadSecondReply(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	monitor.Start(ctx)

	serveOnce := func(mapped bool) (*net.UDPConn, <-chan error) {
		t.Helper()
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 1500)
			_ = server.SetReadDeadline(time.Now().Add(8 * time.Second))
			n, src, err := server.ReadFromUDP(buf)
			if err != nil {
				done <- err
				return
			}
			req := &stunlib.Message{Raw: buf[:n]}
			if err := req.Decode(); err != nil {
				done <- err
				return
			}
			setters := []stunlib.Setter{stunlib.NewTransactionIDSetter(req.TransactionID), stunlib.BindingSuccess}
			if mapped {
				setters = append(setters, &stunlib.XORMappedAddress{IP: net.IPv4(198, 51, 100, 88), Port: 51820})
			}
			resp, err := stunlib.Build(setters...)
			if err != nil {
				done <- err
				return
			}
			_, err = server.WriteToUDP(resp.Raw, src)
			done <- err
		}()
		return server, done
	}
	first, firstDone := serveOnce(false)
	defer first.Close()
	second, secondDone := serveOnce(true)
	defer second.Close()

	if _, _, err := monitor.Connect(ctx, first.LocalAddr().String()); !errors.Is(err, ErrNoMappedAddress) {
		t.Fatalf("first STUN response should lack a mapped endpoint: %v", err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("first server failed to answer: %v", err)
	}
	if _, _, err := monitor.Connect(ctx, second.LocalAddr().String()); !errors.Is(err, ErrTimeout) {
		t.Fatalf("second response should be lost after listener exits: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second server failed to answer: %v", err)
	}
	t.Log("DEMONSTRATED: a valid reply from the second STUN server timed out after the first reply consumed the raw-socket listener")
}

// GHSA-34rh-wp3j-6cxc was a panic in older Pion versions when a decoded
// XOR-MAPPED-ADDRESS attribute had zero bytes at the end of a tight buffer.
// Exercise the actual STUNMESH response parser with the advisory's packet
// shape to confirm that the pinned Pion v3.1.7 returns an error instead.
func TestAuditPinnedPionRejectsShortXORMappedAddress(t *testing.T) {
	raw := []byte{
		0x01, 0x01, 0x00, 0x04, // Binding Success, one four-byte attribute header.
		0x21, 0x12, 0xa4, 0x42, // STUN magic cookie.
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Transaction ID.
		0x00, 0x20, 0x00, 0x00, // XOR-MAPPED-ADDRESS with zero-length value.
	}
	raw = raw[:len(raw):len(raw)]
	host, port, err := parseBindingResponse(context.Background(), raw, [12]byte{})
	if !errors.Is(err, ErrNoMappedAddress) || host != "" || port != 0 {
		t.Fatalf("short XOR-MAPPED-ADDRESS: host=%q port=%d err=%v", host, port, err)
	}
}
