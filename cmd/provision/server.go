package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tjjh89017/stunmesh-go/internal/linuxprofile"
	"github.com/tjjh89017/stunmesh-go/internal/provision"
)

// Phone addresses stay separate from NAS service aliases and Linux client slots.
func phoneAddress(used []string) (string, error) {
	used = append([]string{"10.77.0.21/32", "10.77.0.23/32"}, used...)
	prefixes := make([]netip.Prefix, 0, len(used))
	for _, text := range used {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return "", errors.New("invalid reserved address")
		}
		prefixes = append(prefixes, p)
	}
	for n := 2; n <= 252; n++ {
		ip := netip.AddrFrom4([4]byte{10, 77, 0, byte(n)})
		free := true
		for _, p := range prefixes {
			if p.Contains(ip) {
				free = false
				break
			}
		}
		if free {
			return ip.String() + "/32", nil
		}
	}
	return "", errors.New("phone address pool exhausted")
}

func serverNew(args []string) error {
	f := flag.NewFlagSet("server-new", flag.ContinueOnError)
	config := f.String("config", "", "read-only server configuration directory")
	out := f.String("out", "", "existing private empty output directory")
	name := f.String("name", "", "device name")
	endpoint := f.String("endpoint", "", "reviewed numeric LAN bootstrap endpoint")
	routes := f.String("routes", "", "reviewed comma-separated service routes")
	reserved := f.String("reserved", "", "pending enrollment addresses")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *config == "" || *out == "" || *name == "" || *endpoint == "" {
		return errors.New("missing server enrollment inputs")
	}
	info, err := os.Lstat(*out)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("output directory must be private")
	}
	entries, err := os.ReadDir(*out)
	if err != nil || len(entries) != 0 {
		return errors.New("output directory must be empty")
	}
	server, err := linuxprofile.LoadServer(*config)
	if err != nil {
		return errors.New("cannot validate server configuration")
	}
	used := server.Public()["peer_addresses"].([]string)
	used = append(used, strings.Split(*routes, ",")...)
	if *reserved != "" {
		used = append(used, strings.Split(*reserved, ",")...)
	}
	address, err := phoneAddress(used)
	if err != nil {
		return err
	}
	p := provision.Proposal{Schema: provision.Schema, ID: provision.NewID(), Name: *name,
		Address: address, ServerPublicKey: server.PublicKey, AllowedIPs: strings.Split(*routes, ","),
		STUN: server.STUN, OpenDHT: server.DHT, Endpoint: *endpoint, Protocol: "ipv4"}
	if err = p.Validate(); err != nil {
		return err
	}
	// Capture inside the logging-disabled container; never pass keys in argv/env.
	psk, err := exec.Command("/usr/local/bin/wg", "genpsk").Output()
	if err != nil {
		return errors.New("WireGuard PSK generation failed")
	}
	p.PresharedKey = strings.TrimSpace(string(psk))
	data, err := p.Encode()
	if err != nil {
		return errors.New("invalid generated enrollment")
	}
	created := []string{}
	complete := false
	defer func() {
		if !complete {
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	jsonPath := filepath.Join(*out, "enrollment.json")
	file, err := os.OpenFile(jsonPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create enrollment file")
	}
	created = append(created, jsonPath)
	_, writeErr := file.Write(append(data, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot save enrollment")
	}
	qrPath := filepath.Join(*out, "enrollment.svg")
	qr, err := os.OpenFile(qrPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create QR file")
	}
	created = append(created, qrPath)
	cmd := exec.Command("/usr/local/bin/qrencode", "-t", "SVG", "-l", "M", "-m", "4", "-s", "8", "-r", jsonPath, "-o", "-")
	cmd.Stdout = qr // Encoded credential never goes through container stdout.
	qrErr := cmd.Run()
	syncErr = qr.Sync()
	closeErr = qr.Close()
	if qrErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("QR generation failed")
	}
	complete = true
	summary, _ := json.Marshal(map[string]string{"address": address, "proposal_id": p.ID, "schema": p.Schema})
	fmt.Println(string(summary))
	return nil
}
