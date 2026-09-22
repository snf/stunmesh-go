package ctrl

import (
	"context"
	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/internal/entity"
	"github.com/tjjh89017/stunmesh-go/internal/plugin/dialer"
	"github.com/tjjh89017/stunmesh-go/internal/queue"
	"github.com/tjjh89017/stunmesh-go/internal/wg"
)

type EstablishController struct {
	wgCtrl        WireGuardClient
	devices       DeviceRepository
	peers         PeerRepository
	pluginManager PluginProvider
	deviceConfig  DeviceConfigProvider
	logger        zerolog.Logger
	mu            sync.Mutex
	selection     map[entity.PeerId]*discovery.Selection
	queue         *queue.Queue[entity.PeerId]
}

func NewEstablishController(ctrl WireGuardClient, devices DeviceRepository, peers PeerRepository, pluginManager PluginProvider, deviceConfig DeviceConfigProvider, logger *zerolog.Logger) *EstablishController {
	return &EstablishController{
		wgCtrl:        ctrl,
		devices:       devices,
		peers:         peers,
		pluginManager: pluginManager,
		deviceConfig:  deviceConfig,
		logger:        logger.With().Str("controller", "establish").Logger(),
		selection:     make(map[entity.PeerId]*discovery.Selection),
		queue:         queue.NewBuffered[entity.PeerId](queue.PeerQueueSize),
	}
}

func (c *EstablishController) Execute(ctx context.Context, peerId entity.PeerId) {
	c.mu.Lock()
	defer c.mu.Unlock()

	peer, err := c.peers.Find(ctx, peerId)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to find peer")
		return
	}

	device, err := c.devices.Find(ctx, peer.DeviceName())
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to find device")
		return
	}

	logger := c.logger.With().Str("peer", peer.LocalId()).Str("device", string(device.Name())).Logger()

	store, err := c.pluginManager.GetPlugin(peer.Plugin())
	if err != nil {
		logger.Error().Err(err).Str("plugin", peer.Plugin()).Msg("failed to get plugin")
		return
	}

	storeCtx := dialer.WithEscape(logger.WithContext(ctx), escapeFor(c.deviceConfig, device))
	selection := c.selection[peer.Id()]
	if selection == nil {
		selection = &discovery.Selection{}
		c.selection[peer.Id()] = selection
	}
	if reader, ok := c.wgCtrl.(interface {
		PeerHealth(context.Context, string, wg.Key) (discovery.Health, error)
	}); ok {
		health, err := reader.PeerHealth(ctx, string(device.Name()), peer.PublicKey())
		if err != nil {
			logger.Warn().Msg("WireGuard health unavailable; retaining endpoint")
			return
		}
		if selection.Working(health, time.Now()) {
			return
		}
	}
	records, err := store.Get(storeCtx, peer.RemoteId())
	if err != nil || len(records) == 0 {
		return
	}
	status, known := c.devices.Status(ctx, device.Name())
	var local *entity.DeviceStatus
	if known {
		local = &status
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
		endpoint, err := discovery.SelectEndpoint(data, peer.Protocol(), local)
		if err == nil && discovery.Allowed(endpoint, nil) {
			endpoints = append(endpoints, endpoint)
		}
	}
	selected := selection.Next(endpoints)
	if selected == "" {
		return
	}
	ep, err := validation.Endpoint(selected)
	if err != nil {
		return
	}
	host, port := ep.Addr().String(), int(ep.Port())

	err = c.ConfigureDevice(ctx, peer, host, port)
	if err != nil {
		logger.Error().Err(err).Msg("failed to configure device")
		return
	}
}

func (c *EstablishController) ConfigureDevice(ctx context.Context, peer *entity.Peer, host string, port int) error {
	if _, err := validation.HostPort(host, port); err != nil {
		return err
	}
	remoteEndpoint := host + ":" + strconv.FormatInt(int64(port), 10)
	c.logger.Debug().Str("peer", peer.LocalId()).Str("remote", remoteEndpoint).Msg("configuring device for peer")

	err := c.wgCtrl.UpdatePeerEndpoint(ctx, wg.PeerEndpointUpdate{
		DeviceName: string(peer.DeviceName()),
		PublicKey:  peer.PublicKey(),
		Host:       host,
		Port:       port,
	})
	if err != nil {
		c.logger.Error().Err(err).Str("peer", peer.LocalId()).Str("device", string(peer.DeviceName())).Msg("failed to configure device for peer")
		return err
	}
	c.logger.Debug().Str("peer", peer.LocalId()).Str("device", string(peer.DeviceName())).Msg("device configured for peer")
	return nil
}

// Run starts the worker goroutine that processes establish triggers
func (c *EstablishController) Run(ctx context.Context) {
	c.logger.Info().Msg("establish controller worker started")
	for {
		select {
		case <-ctx.Done():
			c.logger.Info().Msg("establish controller worker stopped")
			return
		case peerId := <-c.queue.Dequeue():
			c.Execute(ctx, peerId)
		}
	}
}

// Trigger lists all peers and enqueues them for establishment
func (c *EstablishController) Trigger(ctx context.Context) {
	peers, err := c.peers.List(ctx)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to list peers")
		return
	}

	enqueued := 0
	for _, peer := range peers {
		if c.queue.TryEnqueue(peer.Id()) {
			enqueued++
		} else {
			c.logger.Warn().Str("peer", peer.Id().PeerPublicKeyString()).Msg("queue full, peer dropped")
		}
	}

	c.logger.Debug().Int("enqueued", enqueued).Int("total", len(peers)).Msg("peers enqueued")
	c.logger.Debug().Int("queue_len", c.queue.Len()).Msg("current queue length")
}

// TriggerForPeer enqueues a specific peer for establishment (non-blocking)
func (c *EstablishController) TriggerForPeer(peerId entity.PeerId) {
	if c.queue.TryEnqueue(peerId) {
		c.logger.Debug().Str("peer", peerId.PeerPublicKeyString()).Msg("establish triggered for peer")
	} else {
		c.logger.Warn().Str("peer", peerId.PeerPublicKeyString()).Msg("establish queue full, dropping trigger for peer")
	}
}

// WaitForCompletion waits until the queue is empty or context is cancelled
func (c *EstablishController) WaitForCompletion(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.queue.Len() == 0 {
				return
			}
		}
	}
}
