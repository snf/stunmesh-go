package discovery

import "time"

// Health is public runtime state reported by WireGuard, never by discovery.
type Health struct {
	Endpoint  string
	Handshake time.Time
	Received  uint64
}

// Selection is bounded per configured peer. No background health worker is
// needed: sample WireGuard only during the ordinary discovery cycle.
type Selection struct {
	received  uint64
	handshake time.Time
	observed  bool
	next      uint64
}

func (s *Selection) Working(h Health, now time.Time) bool {
	fresh := !h.Handshake.IsZero() && !h.Handshake.After(now) && now.Sub(h.Handshake) < 5*time.Minute
	// A historical handshake is not fresh evidence on every refresh. Preserve
	// an endpoint when WG reports a new handshake or authenticated receive
	// progress. The initial observation may use a recent handshake, but not a
	// nonzero historical byte counter by itself.
	handshook := fresh && (!s.observed || h.Handshake.After(s.handshake))
	advanced := s.observed && h.Received > s.received
	s.received = h.Received
	s.handshake = h.Handshake
	s.observed = true
	return h.Endpoint != "" && !h.Handshake.IsZero() && !h.Handshake.After(now) && (handshook || advanced)
}
func (s *Selection) Next(endpoints []string) string {
	if len(endpoints) == 0 {
		return ""
	}
	if len(endpoints) > 4 {
		endpoints = endpoints[:4]
	}
	ep := endpoints[s.next%uint64(len(endpoints))]
	s.next++
	return ep
}

// Reset records the WG counters at an underlay transition. Bytes/handshakes
// accumulated on the previous network cannot keep its endpoint pinned; new
// authenticated traffic can still preserve a session without a new handshake.
func (s *Selection) Reset(h Health) {
	s.next = 0
	s.received = h.Received
	s.handshake = h.Handshake
	s.observed = true
}
