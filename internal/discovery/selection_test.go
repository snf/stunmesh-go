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
	s.Reset()
	if s.Next(endpoints) != "a" {
		t.Fatal("network reset failed")
	}
}
