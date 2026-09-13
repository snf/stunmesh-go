//go:build security_audit

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/tjjh89017/stunmesh-go/internal/config"
)

// A bad local config can abort the daemon instead of failing validation.
func TestAuditZeroRefreshIntervalPanicsAfterConfigAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "refresh_interval: 0s\nstun:\n  addresses: [192.0.2.1:3478]\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, "")
	if err != nil {
		t.Fatalf("zero refresh unexpectedly rejected by config.Load: %v", err)
	}
	if cfg.RefreshInterval != 0 {
		t.Fatalf("loaded interval = %v, want zero", cfg.RefreshInterval)
	}
	logger := zerolog.Nop()
	d := New(cfg, &fakeBootstrap{}, &fakePublish{}, &fakeEstablish{}, &fakePingMonitor{}, &logger)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprint(r), "non-positive interval") {
			t.Fatalf("expected time.NewTicker panic after valid config, got %v", r)
		}
		t.Log("DEMONSTRATED: zero refresh_interval passes config.Load, then aborts Daemon.Run at NewTicker")
	}()
	_ = d.Run(ctx)
}
