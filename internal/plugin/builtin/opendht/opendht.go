// Package opendht exchanges untrusted, public endpoint hints. It never handles
// authentication keys; only WireGuard may authenticate the endpoint it suggests.
package opendht

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tjjh89017/stunmesh-go/internal/discovery"
	"github.com/tjjh89017/stunmesh-go/internal/plugin/builtin"
	"github.com/tjjh89017/stunmesh-go/internal/plugin/dialer"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"github.com/tjjh89017/stunmesh-go/pluginapi"
)

const (
	MaxResponseBytes = 256 * 1024
	MaxRecords       = 64
	MaxCandidates    = 4
	defaultTimeout   = 10 * time.Second
)

var keyPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var errUnavailable = errors.New("OpenDHT has no usable hint")

type OpenDHTPlugin struct {
	endpoints []string
	client    *http.Client
}
type envelope struct {
	Magic string `json:"magic"`
	Data  string `json:"data"`
}
type value struct {
	Data string `json:"data"`
}

func normalizeEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 1024 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("OpenDHT endpoint must be an HTTPS origin without credentials, path, query or fragment")
	}
	if u.Port() != "" {
		if err := validation.Server(u.Host); err != nil {
			return "", errors.New("invalid OpenDHT endpoint port")
		}
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func NewOpenDHTPlugin(config pluginapi.PluginConfig) (pluginapi.Store, error) {
	if err := pluginapi.ValidateDefinition(pluginapi.PluginDefinition{Type: "builtin", Config: config}); err != nil {
		return nil, err
	}
	cfg := builtin.NewConfig(config)
	list, err := cfg.GetStringSlice("endpoints")
	if err != nil {
		return nil, errors.New("invalid OpenDHT endpoints")
	}
	single, _ := cfg.GetString("endpoint")
	if single != "" {
		list = append([]string{single}, list...)
	}
	if len(list) == 0 || len(list) > 8 {
		return nil, errors.New("OpenDHT requires one to eight proxy endpoints")
	}
	endpoints := []string{}
	seen := map[string]bool{}
	for _, s := range list {
		e, err := normalizeEndpoint(s)
		if err != nil {
			return nil, err
		}
		if !seen[e] {
			seen[e] = true
			endpoints = append(endpoints, e)
		}
	}
	timeout, ok, err := cfg.GetDuration("timeout")
	if err != nil {
		return nil, errors.New("invalid OpenDHT timeout")
	}
	if !ok {
		timeout = defaultTimeout
	}
	if timeout < time.Second || timeout > 20*time.Second {
		return nil, errors.New("OpenDHT timeout must be between 1s and 20s")
	}
	return &OpenDHTPlugin{endpoints: endpoints, client: &http.Client{Timeout: timeout, Transport: dialer.Transport(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (p *OpenDHTPlugin) request(ctx context.Context, endpoint, method, key string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint+"/key/"+key, bytes.NewReader(body))
	if err != nil {
		return nil, errUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errUnavailable
	}
	// net/http transparently decompresses gzip. Bound the decoded body, too.
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil || len(b) > MaxResponseBytes {
		return nil, errUnavailable
	}
	return b, nil
}

// Parse at most 64 proxy records and retain four distinct valid candidates.
// Neither ordering nor publisher timestamps claim freshness or authentication.
func candidates(data []byte) []string {
	if len(data) > MaxResponseBytes {
		return nil
	}
	lines := bytes.Split(data, []byte("\n"))
	count := 0
	found := map[string]bool{}
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		count++
		if count > MaxRecords {
			return nil
		}
		// Proxies may include their own metadata. Only data is interpreted here.
		var outer map[string]json.RawMessage
		if validation.DecodeJSON(line, &outer) != nil {
			continue
		}
		var encoded string
		if json.Unmarshal(outer["data"], &encoded) != nil || len(encoded) > 4096 {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			continue
		}
		var e envelope
		if validation.DecodeJSON(raw, &e) != nil || e.Magic != discovery.Namespace {
			continue
		}
		record, err := discovery.Decode(e.Data)
		if err != nil {
			continue
		}
		canonical, err := discovery.Encode(record)
		if err != nil {
			continue
		}
		found[canonical] = true
	}
	result := make([]string, 0, len(found))
	for r := range found {
		result = append(result, r)
	}
	sort.Strings(result)
	if len(result) > MaxCandidates {
		result = result[:MaxCandidates]
	}
	return result
}

func (p *OpenDHTPlugin) Get(ctx context.Context, key string) ([]string, error) {
	if !keyPattern.MatchString(key) {
		return nil, errors.New("invalid discovery key")
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	for _, endpoint := range p.endpoints {
		data, err := p.request(ctx, endpoint, http.MethodGet, key, nil)
		if err == nil {
			if result := candidates(data); len(result) > 0 {
				return result, nil
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errUnavailable
}
func (p *OpenDHTPlugin) Set(ctx context.Context, key, record string) error {
	if !keyPattern.MatchString(key) {
		return errors.New("invalid discovery key")
	}
	r, err := discovery.Decode(record)
	if err != nil {
		return errors.New("invalid discovery record")
	}
	canonical, _ := discovery.Encode(r)
	raw, _ := json.Marshal(envelope{Magic: discovery.Namespace, Data: canonical})
	body, _ := json.Marshal(value{Data: base64.StdEncoding.EncodeToString(raw)})
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	for _, endpoint := range p.endpoints {
		if _, err := p.request(ctx, endpoint, http.MethodPost, key, body); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errUnavailable
}
func (p *OpenDHTPlugin) Close() error { p.client.CloseIdleConnections(); return nil }
