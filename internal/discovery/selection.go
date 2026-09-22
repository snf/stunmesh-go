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
	received uint64
	next     uint64
}

func (s *Selection) Working(h Health, now time.Time) bool {
	fresh := !h.Handshake.IsZero() && !h.Handshake.After(now) && now.Sub(h.Handshake) < 5*time.Minute
	advanced := h.Received > s.received
	s.received = h.Received
	return h.Endpoint != "" && (fresh || advanced)
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
func (s *Selection) Reset() { s.next = 0; s.received = 0 }
