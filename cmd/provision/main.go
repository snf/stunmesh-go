// Local provisioning tool. A proposal may contain a PSK; replies are public.
// Never included in the service image. Never accepts a phone private key.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tjjh89017/stunmesh-go/internal/linuxprofile"
	"github.com/tjjh89017/stunmesh-go/internal/provision"
)

func read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("cannot open enrollment input")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, provision.MaxBytes+1))
	return b, e
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 1 && args[0] == "linux" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, linuxprofile.MaxBytes+1))
		if err != nil {
			return errors.New("cannot read issuance template")
		}
		b, err = linuxprofile.Issue(b, "/usr/local/bin/wg")
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: provision new|reply [flags]; -h lists required inputs")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	if args[0] == "new" {
		var p provision.Proposal
		p.Schema = provision.Schema
		p.ID = provision.NewID()
		f.StringVar(&p.Name, "name", "Server", "display name")
		f.StringVar(&p.Address, "address", "", "phone's dedicated /32 or /128 tunnel address")
		f.StringVar(&p.ServerPublicKey, "server-key", "", "trusted server WG public key")
		routes := f.String("routes", "", "comma-separated narrow server destinations")
		stun := f.String("stun", "", "comma-separated STUN host:port entries")
		dht := f.String("opendht", "", "comma-separated HTTPS proxy origins")
		f.StringVar(&p.Endpoint, "endpoint", "", "optional numeric static server endpoint")
		f.StringVar(&p.Protocol, "protocol", "ipv4", "ipv4, ipv6, prefer_ipv4, prefer_ipv6")
		pskFile := f.String("psk-file", "", "optional PSK file, or - for stdin; output/QR becomes confidential")
		out := f.String("out", "", "new owner-private JSON file; must not already exist")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 || *out == "" {
			return errors.New("specify --out and enrollment inputs")
		}
		p.AllowedIPs = strings.Split(*routes, ",")
		p.STUN = strings.Split(*stun, ",")
		p.OpenDHT = strings.Split(*dht, ",")
		if *pskFile != "" {
			var input io.Reader = os.Stdin
			if *pskFile != "-" {
				file, err := os.Open(*pskFile)
				if err != nil {
					return errors.New("cannot open PSK input")
				}
				defer file.Close()
				input = file
			}
			b, err := io.ReadAll(io.LimitReader(input, 65))
			if err != nil {
				return errors.New("cannot read PSK input")
			}
			p.PresharedKey = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
			if p.PresharedKey == "" {
				return errors.New("empty PSK input")
			}
		}
		b, err := p.Encode()
		if err != nil {
			return err
		}
		file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot create new enrollment output")
		}
		_, err = file.Write(append(b, '\n'))
		closeErr := file.Close()
		return errors.Join(err, closeErr)
	}
	if args[0] == "reply" {
		proposalFile := f.String("proposal", "", "original proposal JSON (may contain a PSK)")
		replyFile := f.String("reply", "", "public reply copied from the phone")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		pb, err := read(*proposalFile)
		if err != nil {
			return err
		}
		p, err := provision.Decode(pb)
		if err != nil {
			return err
		}
		rb, err := read(*replyFile)
		if err != nil {
			return err
		}
		r, err := provision.CheckReply(p, rb)
		if err != nil {
			return err
		}
		// Deliberately no shell commands or automatic server changes. Public JSON
		// is safe to compare; an owner must still approve the actual peer entry.
		b, _ := json.MarshalIndent(struct {
			Reply       provision.Reply `json:"public_reply"`
			PSKRequired bool            `json:"psk_required"`
			Review      string          `json:"review"`
		}{r, p.PresharedKey != "", "Compare phone/server public keys over your trusted local channel. Add PublicKey and this exact phone address to WG and the OpenDHT overlay in the server Git repository. If the proposal includes a PSK, configure that same PSK on the server without exporting it in this public reply."}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	return errors.New("expected new or reply")
}
