//go:build mobile && (linux || android)

package mobile

import "errors"

// SetUnderlay is driven by Android non-VPN callbacks. Offline closes WG sockets
// and timers as well as suspending discovery. Handover rebinds outer sockets,
// preserving the TUN and authorized peer configuration.
func (n *Node) SetUnderlay(online, ipv4, ipv6, rebind bool) error {
	n.lifecycle.Lock()
	defer n.lifecycle.Unlock()
	state := underlayState{online: online, ipv4: ipv4, ipv6: ipv6}
	n.mu.Lock()
	previous := n.network
	n.network = state
	c := n.ctrl
	n.mu.Unlock()
	if c != nil {
		c.networkChanged(state)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.dev == nil || !n.running {
		return nil
	}
	var err error
	if !online {
		err = n.dev.Down()
	} else if !previous.online {
		err = n.dev.Up()
	} else if rebind {
		err = n.dev.BindUpdate()
	}
	if err != nil {
		n.dev.Close()
		go n.Stop()
		return errors.New("underlay transition failed; device stopped")
	}
	if online && rebind {
		n.dev.SendKeepalivesToPeersWithCurrentKeypair()
	}
	return nil
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
