package discovery

import (
	"testing"
	"time"
)

func TestAuthenticatedHealthPreservedAndFailedCandidatesRotate(t *testing.T) {
	now := time.Now()
	s := &Selection{}
	h := Health{Endpoint: "198.51.100.1:4", Handshake: now.Add(-time.Minute), Received: 10}
	if !s.Working(h, now) {
		t.Fatal("fresh authenticated session not preserved")
	}
	h.Handshake = now.Add(-time.Hour)
	if s.Working(h, now) {
		t.Fatal("stale session assumed healthy")
	}
	h.Received++
	if !s.Working(h, now) {
		t.Fatal("authenticated receive progress ignored")
	}
	endpoints := []string{"a", "b", "c", "d", "e"}
	for i := 0; i < 12; i++ {
		if s.Next(endpoints) != endpoints[i%4] {
			t.Fatal("candidate bound/rotation failed")
		}
	}
	if s.Next(nil) != "" {
		t.Fatal("empty candidates")
	}
	s.Reset(h)
	if s.Next(endpoints) != "a" {
		t.Fatal("network reset failed")
	}
}

func TestUnchangedHandshakeDoesNotPinFailedEndpointAcrossRefreshes(t *testing.T) {
	now := time.Now()
	s := &Selection{}
	h := Health{Endpoint: "192.168.0.20:39788", Handshake: now.Add(-time.Minute), Received: 100}
	if !s.Working(h, now) {
		t.Fatal("initial recent WG handshake should preserve the endpoint")
	}
	if s.Working(h, now.Add(3*time.Minute)) {
		t.Fatal("unchanged historical handshake pinned the old network endpoint")
	}
	h.Handshake = now.Add(3 * time.Minute)
	if !s.Working(h, now.Add(3*time.Minute)) {
		t.Fatal("new WG handshake was ignored")
	}
}

func TestUnderlayResetRequiresNewAuthenticatedProgress(t *testing.T) {
	now := time.Now()
	s := &Selection{}
	h := Health{Endpoint: "198.51.100.1:1234", Handshake: now.Add(-time.Minute), Received: 100}
	s.Working(h, now)
	h.Received = 1000 // More traffic before the underlay transition.
	s.Reset(h)
	if s.Working(h, now) {
		t.Fatal("old handshake/traffic survived the underlay health reset")
	}
	h.Received += 32 // WG can authenticate traffic using its existing session.
	if !s.Working(h, now) {
		t.Fatal("new authenticated receive progress after handover was ignored")
	}
	if s.Working(h, now.Add(3*time.Minute)) {
		t.Fatal("one received packet was reused as progress indefinitely")
	}
}

func TestCountersAloneCannotEstablishInitialHealth(t *testing.T) {
	now := time.Now()
	for _, handshake := range []time.Time{{}, now.Add(-time.Hour), now.Add(time.Hour)} {
		s := &Selection{}
		h := Health{Endpoint: "198.51.100.1:1234", Handshake: handshake, Received: 100}
		if s.Working(h, now) {
			t.Fatal("historical counter established initial health")
		}
	}
	s := &Selection{}
	h := Health{Endpoint: "198.51.100.1:1234", Received: 100}
	s.Working(h, now)
	h.Received++
	if s.Working(h, now) {
		t.Fatal("receive counter without a completed handshake established health")
	}
}
