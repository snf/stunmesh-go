package wg

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
)

func TestPublicInfoNeverReadsSecrets(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes32(7))
	fields := []string{}
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != "wg0" {
			t.Fatal("unexpected command")
		}
		fields = append(fields, args[2])
		switch args[2] {
		case "public-key", "peers":
			return []byte(key), nil
		case "listen-port":
			return []byte("51820"), nil
		case "fwmark":
			return []byte("0xca6c"), nil
		default:
			t.Fatal("command could expose secrets")
			return nil, errors.New("bad")
		}
	}
	info, err := publicInfo(context.Background(), "wg0", runner)
	if err != nil {
		t.Fatal(err)
	}
	if info.ListenPort != 51820 || info.FirewallMark != 0xca6c || len(info.PeerKeys) != 1 || !reflect.DeepEqual(fields, []string{"public-key", "listen-port", "fwmark", "peers"}) {
		t.Fatal("incomplete public metadata")
	}
	for _, name := range []string{"-all", "wg0\nprivate-key", "wg0/else", ""} {
		if _, err := publicInfo(context.Background(), name, runner); err == nil {
			t.Fatal("invalid interface accepted")
		}
	}
}
func TestPublicInfoBounds(t *testing.T) {
	var b boundedOutput
	if _, err := b.Write(make([]byte, 16385)); err == nil {
		t.Fatal("unbounded tool output")
	}
}
