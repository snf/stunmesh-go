package linuxprofile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tjjh89017/stunmesh-go/app"
)

// Runtime has fixed production commands. Tests substitute these only inside an
// isolated namespace. No command or path is read from the enrollment profile.
type Runtime struct {
	IP []string
	WG string
}

func Native() Runtime { return Runtime{[]string{"/bin/busybox", "ip"}, "/usr/local/bin/wg"} }
func (r Runtime) ip(args ...string) error {
	if err := exec.Command(r.IP[0], append(r.IP[1:], args...)...).Run(); err != nil {
		return errors.New("owned interface/route operation failed")
	}
	return nil
}

// Cleanup fails closed on a foreign interface, including an unconfigured
// interface left by a crash before setconf. Never flush routes.
func (r Runtime) Cleanup(p Profile) error {
	out, err := exec.Command(r.WG, "show", Interface, "public-key").Output()
	if err != nil {
		if r.ip("link", "show", "dev", Interface) != nil {
			return nil
		}
		return errors.New("cannot establish interface ownership")
	}
	if strings.TrimSpace(string(out)) != p.PublicKey() {
		return errors.New("refusing to remove another WireGuard identity")
	}
	return r.ip("link", "delete", "dev", Interface)
}

func (r Runtime) Setup(p Profile, dir string) (err error) {
	if err = p.Validate(); err != nil {
		return err
	}
	if err = r.ip("link", "add", Interface, "type", "wireguard"); err != nil {
		return err
	}
	// Exclusive creation establishes ownership even before setconf.
	defer func() {
		if err != nil {
			_ = r.ip("link", "delete", "dev", Interface)
		}
	}()
	if err = WriteNew(filepath.Join(dir, "wg.conf"), p.WireGuard()); err != nil {
		return err
	}
	if err = exec.Command(r.WG, "setconf", Interface, filepath.Join(dir, "wg.conf")).Run(); err != nil {
		return errors.New("native WireGuard configuration failed")
	}
	if err = r.ip("address", "add", p.Address, "dev", Interface); err != nil {
		return err
	}
	if err = r.ip("link", "set", "dev", Interface, "mtu", "1280", "up"); err != nil {
		return err
	}
	for _, route := range p.AllowedIPs {
		if err = r.ip("route", "add", route, "dev", Interface, "metric", "50", "proto", "186"); err != nil {
			return err
		}
	}
	return nil
}

func Run(ctx context.Context, p Profile) error {
	dir, err := os.MkdirTemp("/run", "wg-")
	if err != nil {
		return errors.New("cannot allocate private runtime directory")
	}
	defer os.RemoveAll(dir)
	r := Native()
	if err = r.Setup(p, dir); err != nil {
		return err
	}
	defer r.Cleanup(p)
	yml, err := p.Discovery()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "stunmesh.yml")
	if err = WriteNew(path, yml); err != nil {
		return err
	}
	d, err := app.New(app.Options{ConfigFile: path})
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Run(ctx)
}
