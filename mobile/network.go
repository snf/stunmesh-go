//go:build mobile && (linux || android)

package mobile

// SetUnderlay is called by Android's non-VPN network callback, including once
// before Start. No discovery runs while offline. Family availability comes from
// the selected network's LinkProperties, avoiding repeated impossible IPv6 probes.
func (n *Node) SetUnderlay(online, ipv4, ipv6 bool) {
	n.mu.Lock()
	n.network = underlayState{online: online, ipv4: ipv4, ipv6: ipv6}
	c := n.ctrl
	n.mu.Unlock()
	if c != nil {
		c.networkChanged(underlayState{online: online, ipv4: ipv4, ipv6: ipv6})
	}
}

type underlayState struct{ online, ipv4, ipv6 bool }

func (c *controller) networkChanged(state underlayState) {
	c.networkMu.Lock()
	c.network = state
	if c.cycleCancel != nil {
		c.cycleCancel()
	}
	c.networkMu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
}
