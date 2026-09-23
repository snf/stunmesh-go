package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/tjjh89017/stunmesh-go/app"
	"github.com/tjjh89017/stunmesh-go/internal/config"
	"github.com/tjjh89017/stunmesh-go/internal/linuxprofile"
)

var buildVersion = "dev"

// version comes from the VCS build info the Go toolchain stamps into the
// binary: the exact tag when built at one, a pseudo-version otherwise.
func version() string {
	if buildVersion != "dev" {
		return buildVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "STUNMESH stopped: check configuration and interface permissions")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "linux-") {
		return linuxCommand(os.Args[1:])
	}
	var (
		oneshot     bool
		showVersion bool
		configFile  string
		configDir   string
	)

	// -c and --config are the same destination, so the usage text is shared.
	const configFileUsage = "path to the config file (takes priority over --config-dir)"

	flag.BoolVar(&oneshot, "oneshot", false, "run in oneshot mode (publish and establish 3 times, then exit)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.StringVar(&configFile, "c", "", configFileUsage)
	flag.StringVar(&configFile, "config", "", configFileUsage)
	flag.StringVar(&configDir, "config-dir", "", "directory containing config.yaml (ignored if -c/--config is set)")

	flag.Parse()

	if showVersion {
		fmt.Println(version())
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	daemon, err := app.New(app.Options{ConfigFile: configFile, ConfigDir: configDir})
	if err != nil {
		return err
	}
	defer daemon.Close()

	if oneshot {
		if err := daemon.RunOneshot(ctx); err != nil {
			return err
		}
		return nil
	}

	if err := daemon.Run(ctx); err != nil {
		return err
	}
	return nil
}

func linuxCommand(args []string) error {
	if len(args) == 2 && args[0] == "linux-config-check" {
		_, err := config.Load(args[1], "")
		return err
	}
	if len(args) == 2 && (args[0] == "linux-server" || args[0] == "linux-activate" || args[0] == "linux-revoke") {
		s, err := linuxprofile.LoadServer(args[1])
		if err != nil {
			return err
		}
		if args[0] == "linux-server" {
			return json.NewEncoder(os.Stdout).Encode(s.Public())
		}
		p, err := linuxprofile.Read(os.Stdin)
		if err != nil {
			return err
		}
		b, err := s.Edited(p, args[0] == "linux-revoke")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	}
	if args[0] == "linux-issue" && len(args) == 1 {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, linuxprofile.MaxBytes+1))
		if err != nil {
			return err
		}
		b, err = linuxprofile.Issue(b, "/usr/local/bin/wg")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	if args[0] == "linux-check" && len(args) == 1 {
		p, err := linuxprofile.Read(os.Stdin)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(p.Public())
	}
	if len(args) != 2 || (args[0] != "linux-run" && args[0] != "linux-clean" && args[0] != "linux-run-owned" && args[0] != "linux-clean-owned") {
		return errors.New("invalid Linux operation")
	}
	p, err := linuxprofile.Load(args[1])
	if err != nil {
		return err
	}
	if args[0] == "linux-clean" {
		return linuxprofile.Native().Cleanup(p)
	}
	if args[0] == "linux-clean-owned" {
		return linuxprofile.Native().CleanupOwned(p, linuxprofile.OwnershipFile)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if args[0] == "linux-run-owned" {
		return linuxprofile.RunOwned(ctx, p)
	}
	return linuxprofile.Run(ctx, p)
}
