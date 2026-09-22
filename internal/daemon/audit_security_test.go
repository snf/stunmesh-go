//go:build security_audit

package daemon

import (
	"github.com/tjjh89017/stunmesh-go/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditZeroRefreshRejectedBeforeDaemon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("refresh_interval: 0s\nstun:\n  addresses: [192.0.2.1:3478]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path, ""); err == nil {
		t.Fatal("zero refresh accepted")
	}
}
