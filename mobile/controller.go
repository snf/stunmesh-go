//go:build mobile && (linux || android)

package mobile

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/tjjh89017/stunmesh-go/internal/ctrl"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	"github.com/tjjh89017/stunmesh-go/internal/mobilebind"
	"github.com/tjjh89017/stunmesh-go/internal/plugin"
	"github.com/tjjh89017/stunmesh-go/internal/plugin/dialer"
	pluginapi "github.com/tjjh89017/stunmesh-go/pluginapi"
)

// stunDiscoverer resolves a reflexive address for one address family via
// STUN. *mobilebind.Bind implements it in production over the shared WG
// socket; tests substitute a fake to exercise discover/discoverFamily
// without a real network.
type stunDiscoverer interface {
	Discover(ctx context.Context, dst netip.AddrPort) (netip.AddrPort, error)
}

// How long one STUN server gets: first to resolve its name, then to answer
// the binding request. Separate budgets so a slow lookup cannot eat the
// probe's retransmit schedule (RFC 8489 RTO doubling, ~7.5s worst case).
const (
	stunResolveTimeout = 5 * time.Second
	stunProbeTimeout   = 10 * time.Second
)

// controller runs the STUNMESH publish/establish cycle on top of the running
// device: discover the reflexive address through the shared socket, publish
// a public hint and fetch bounded peers' hints,
// and apply their endpoints over UAPI.
//
// This is a compact mobile counterpart of the desktop controllers
// (internal/ctrl); it reuses the same public record schema, storage key, store
// manager and endpoint JSON, so mobile and desktop nodes interoperate.
type controller struct {
	node    *Node
	cfg     *controllerConfig
	bind    stunDiscoverer
	manager *plugin.Manager

	pub [32]byte

	pluginDefs   map[string]pluginapi.PluginDefinition
	pluginsReady bool

	selection map[string]*discovery.Selection

	networkMu   sync.Mutex
	network     underlayState
	changed     chan struct{}
	cycleCancel context.CancelFunc
	cancel      context.CancelFunc
	done        chan struct{}
}

// The discovery view contains no private key or PSK.
type discoveryPeer struct{ Name, PublicKey, Plugin, Protocol string }
type controllerConfig struct {
	Interface              struct{ Protocol string }
	Stun                   stunConfig
	RefreshIntervalSeconds int
	Peers                  []discoveryPeer
}

func newController(node *Node, bind *mobilebind.Bind, pub [32]byte) (*controller, error) {
	cfg := node.cfg
	view := &controllerConfig{Stun: cfg.Stun, RefreshIntervalSeconds: cfg.RefreshIntervalSeconds}
	view.Interface.Protocol = cfg.Interface.Protocol
	for _, p := range cfg.Peers {
		view.Peers = append(view.Peers, discoveryPeer{Name: p.Name, PublicKey: p.PublicKey, Plugin: p.Plugin, Protocol: p.Protocol})
	}

	defs := make(map[string]pluginapi.PluginDefinition, len(cfg.Plugins))
	for _, d := range cfg.Plugins {
		conf := pluginapi.PluginConfig{"name": d.Name}
		for k, v := range d.Config {
			conf[k] = v
		}
		defs[d.Instance] = pluginapi.PluginDefinition{Type: d.Type, Config: conf}
	}

	return &controller{
		node:       node,
		cfg:        view,
		bind:       bind,
		manager:    plugin.NewManager(),
		pub:        pub,
		pluginDefs: defs,
		selection:  make(map[string]*discovery.Selection),
		done:       make(chan struct{}),
		network:    node.network, changed: make(chan struct{}, 1),
	}, nil
}

func (c *controller) start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go c.run(ctx)
}

// stop cancels the loop and waits for the current cycle to finish. Must not
// be called with the node mutex held: a running cycle may be blocked on it.
func (c *controller) stop() {
	c.cancel()
	<-c.done
	if err := c.manager.Close(); err != nil {
		c.node.listener.OnLog("warn", "discovery operation failed")
	}
}

func (c *controller) run(ctx context.Context) {
	defer close(c.done)
	timer := time.NewTimer(0)
	defer timer.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.changed:
			failures = 0
			for _, s := range c.selection {
				s.Reset()
			}
			// Coalesce a LinkProperties/capability burst into one cycle.
			timer.Reset(time.Second)
			continue
		case <-timer.C:
		}
		cycleCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		c.networkMu.Lock()
		state := c.network
		c.cycleCancel = cancel
		c.networkMu.Unlock()
		if !state.online {
			cancel()
			continue
		} // no timer while disconnected
		ok := c.cycle(cycleCtx)
		cancel()
		c.networkMu.Lock()
		c.cycleCancel = nil
		c.networkMu.Unlock()
		if ok {
			failures = 0
		} else {
			failures++
		}
		seconds := c.cfg.RefreshIntervalSeconds
		if failures > 0 {
			seconds = 20 << min(failures-1, 4)
			if seconds > 240 {
				seconds = 240
			}
		}
		// Less than four minutes keeps healthy publications inside the 600s TTL.
		seconds = max(10, min(240, seconds-5+rand.IntN(11)))
		timer.Reset(time.Duration(seconds) * time.Second)
	}
}

func (c *controller) cycle(ctx context.Context) bool {
	listener := c.node.listener

	// Plugin init can need the network (e.g. a zone lookup), so it retries
	// each cycle until it succeeds. This only protects the LoadPlugins call
	// boundary -- factory ctors aren't ctx-threaded, so Store.Get/Set (via
	// publish/establish's storeCtx) remain the real protected network path.
	if !c.pluginsReady {
		loadCtx := protectedContext(ctx, c.node.protector, c.node.pluginDNSServers())
		if err := c.manager.LoadPlugins(loadCtx, c.pluginDefs); err != nil {
			listener.OnLog("warn", "discovery operation failed")
			return false
		}
		c.pluginsReady = true
	}

	data, err := c.discover(ctx)
	var local *entity.DeviceStatus
	if err != nil {
		listener.OnLog("warn", "discovery operation failed")
	} else {
		c.publish(ctx, data)
		local = &entity.DeviceStatus{IPv4: data.IPv4, IPv6: data.IPv6}
	}
	c.establish(ctx, local)
	return err == nil && ctx.Err() == nil
}

// discover resolves the reflexive addresses the interface protocol asks for,
// trying each configured STUN server until one answers. The resolution and
// dualstack partial-failure policy live in the shared ctrl.DiscoverEndpoints
// (internal/ctrl/discover.go), which also backs the desktop publish
// controller: a single-family protocol errors out on that family's failure,
// while dualstack tolerates one family failing as long as the other
// succeeds, warning about the failed one instead of erroring.
func (c *controller) discover(ctx context.Context) (ctrl.EndpointData, error) {
	listener := c.node.listener

	resolve := func(network, family string) ctrl.FamilyResolver {
		return func(ctx context.Context) (string, error) {
			ep, err := c.discoverFamily(ctx, network)
			if err != nil {
				return "", err
			}
			listener.OnEvent("endpoint_discovered", "", family+" "+ep)
			return ep, nil
		}
	}
	warn := func(family string, err error) {
		listener.OnLog("warn", family+" discovery unavailable")
	}

	var data ctrl.EndpointData
	var err error
	data.IPv4, data.IPv6, err = ctrl.DiscoverEndpoints(ctx, c.cfg.Interface.Protocol, warn, resolve("udp4", "ipv4"), resolve("udp6", "ipv6"))
	return data, err
}

func (c *controller) discoverFamily(ctx context.Context, network string) (string, error) {
	c.networkMu.Lock()
	state := c.network
	c.networkMu.Unlock()
	if !state.online || network == "udp4" && !state.ipv4 || network == "udp6" && !state.ipv6 {
		return "", fmt.Errorf("underlay family unavailable")
	}

	var lastErr error
	for _, server := range c.cfg.Stun.Addresses {
		addr, err := c.probeServer(ctx, network, server)
		if err != nil {
			lastErr = err
			continue
		}
		return addr.String(), nil
	}
	return "", fmt.Errorf("all stun servers failed: %w", lastErr)
}

// probeServer resolves one configured STUN server for the family and sends it
// a binding request from the shared socket. A server configured for the other
// family resolves to nothing here and is reported as a failure, which is how
// discoverFamily walks a mixed-family list down to the entries that apply.
func (c *controller) probeServer(ctx context.Context, network, server string) (netip.AddrPort, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, stunResolveTimeout)
	dst, err := c.resolveSTUN(resolveCtx, network, server)
	cancel()
	if err != nil {
		return netip.AddrPort{}, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, stunProbeTimeout)
	defer cancel()
	return c.bind.Discover(probeCtx, dst)
}

// resolveSTUN turns a configured STUN server ("host:port", host a name or an
// IP literal) into the address to probe for network ("udp4" or "udp6").
//
// The lookup takes the plugin dialer's escaped path -- a protected socket
// aimed at the underlay's resolvers (Node.SetDNSServers) -- rather than the
// platform's. On android the platform resolver goes through Bionic's
// getaddrinfo, which resolves over the default network; once the tunnel is up
// that is the tunnel, so discovery's own lookup gets routed into the very
// tunnel it is trying to establish. That fails until something else happens
// to bring the tunnel up, which is exactly the ordering that left a
// dualstack node with no IPv6 endpoint on its first cycle: IPv4 discovery ran
// while the tunnel was still down and answered, IPv6 discovery ran after and
// could not resolve.
func (c *controller) resolveSTUN(ctx context.Context, network, server string) (netip.AddrPort, error) {
	escaped := protectedContext(ctx, c.node.protector, c.node.pluginDNSServers())
	return dialer.ResolveAddrPort(escaped, network, server)
}

func (c *controller) publish(ctx context.Context, data ctrl.EndpointData) {
	listener := c.node.listener
	record, err := discovery.Encode(data)
	if err != nil {
		listener.OnLog("warn", "invalid local discovery result")
		return
	}

	for _, peer := range c.cfg.Peers {
		peerPub, err := keyToBytes(peer.PublicKey)
		if err != nil {
			continue
		}
		peerId := entity.NewPeerId(c.pub[:], peerPub[:])
		localId := peerId.EndpointKey()

		store, err := c.manager.GetPlugin(peer.Plugin)
		if err != nil {
			listener.OnLog("warn", "discovery operation failed")
			continue
		}
		storeCtx := protectedContext(ctx, c.node.protector, c.node.pluginDNSServers())
		if err := store.Set(storeCtx, localId, record); err != nil {
			listener.OnLog("warn", "discovery operation failed")
			continue
		}
		listener.OnEvent("publish_ok", peer.PublicKey, localId)
	}
}

// establish validates and applies each peer's public endpoint hint. local is the
// local host's own last STUN discovery result (nil if unknown or the last
// discovery cycle failed), passed through to ctrl.SelectEndpoint so a
// family the local host cannot reach is not selected.
func (c *controller) establish(ctx context.Context, local *entity.DeviceStatus) {
	listener := c.node.listener
	health, err := c.node.peerHealth()
	if err != nil {
		return
	}
	for _, peer := range c.cfg.Peers {
		peerPub, err := keyToBytes(peer.PublicKey)
		if err != nil {
			continue
		}
		peerId := entity.NewPeerId(c.pub[:], peerPub[:])

		store, err := c.manager.GetPlugin(peer.Plugin)
		if err != nil {
			continue
		}
		selection := c.selection[peer.PublicKey]
		if selection == nil {
			selection = &discovery.Selection{}
			c.selection[peer.PublicKey] = selection
		}
		status, exists := health[peer.PublicKey]
		if !exists {
			continue
		}
		if selection.Working(status, time.Now()) {
			listener.OnEvent("peer_authenticated", peer.PublicKey, "")
			continue
		}
		storeCtx := protectedContext(ctx, c.node.protector, c.node.pluginDNSServers())
		records, err := store.Get(storeCtx, peerId.RemoteEndpointKey())
		if err != nil || len(records) == 0 {
			listener.OnLog("debug", "peer hint unavailable")
			continue
		}
		endpoints := []string{}
		for _, record := range records {
			if len(endpoints) == 4 {
				break
			}
			data, err := discovery.Decode(record)
			if err != nil {
				continue
			}
			endpoint, err := ctrl.SelectEndpoint(data, peer.Protocol, local)
			if err == nil && discovery.Allowed(endpoint, nil) {
				endpoints = append(endpoints, endpoint)
			}
		}
		endpoint := selection.Next(endpoints)
		if endpoint == "" || endpoint == status.Endpoint {
			continue
		}

		if err := c.node.SetPeerEndpoint(peer.PublicKey, endpoint); err != nil {
			listener.OnLog("error", "discovery operation failed")
			continue
		}
	}
}
