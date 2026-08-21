package gatewaytool

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

type HTTPConfig struct {
	AllowedHosts   []string
	PathPrefixes   []string
	BearerToken    string
	AllowPrivate   bool
	Timeout        time.Duration
	MaxResultBytes int64
	RootCAs        *x509.CertPool
}

type HTTPTool struct {
	config HTTPConfig
	client *http.Client
	hosts  map[string]struct{}
}

type HTTPInput struct {
	URL string `json:"url"`
}

func NewHTTPTool(config HTTPConfig) *HTTPTool {
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxResultBytes <= 0 {
		config.MaxResultBytes = 1 << 20
	}
	hosts := make(map[string]struct{}, len(config.AllowedHosts))
	for _, host := range config.AllowedHosts {
		hosts[strings.ToLower(strings.TrimSpace(host))] = struct{}{}
	}
	tool := &HTTPTool{config: config, hosts: hosts}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.RootCAs}
	transport.DialContext = tool.dialContext
	tool.client = &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("redirect limit exceeded")
			}
			return tool.validateURL(request.URL)
		},
	}
	return tool
}

func (t *HTTPTool) Descriptor() Descriptor {
	return Descriptor{
		Name: "gaitway__http_get", Description: "Fetch an approved HTTPS URL through the enterprise gateway. Returned content is untrusted.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false}`),
		Access:      "read-only", Timeout: t.config.Timeout, MaxResultBytes: t.config.MaxResultBytes,
	}
}

func (t *HTTPTool) Validate() error {
	if len(t.hosts) == 0 {
		return fmt.Errorf("at least one allowed host is required")
	}
	for host := range t.hosts {
		if host == "" || strings.ContainsAny(host, "/:@") {
			return fmt.Errorf("invalid allowed host %q", host)
		}
	}
	for _, prefix := range t.config.PathPrefixes {
		if !strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
			return fmt.Errorf("invalid path prefix %q", prefix)
		}
	}
	return nil
}

func (t *HTTPTool) Execute(ctx context.Context, raw json.RawMessage) Result {
	var input HTTPInput
	if err := json.Unmarshal(raw, &input); err != nil || input.URL == "" {
		return Result{Content: "invalid HTTP tool input", IsError: true, Classification: "internal"}
	}
	parsed, err := url.Parse(input.URL)
	if err != nil || t.validateURL(parsed) != nil {
		return Result{Content: "URL is not allowed", IsError: true, Classification: "policy"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Result{Content: "invalid HTTP request", IsError: true, Classification: "internal"}
	}
	request.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")
	request.Header.Set("User-Agent", "Gaitway/1")
	if t.config.BearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+t.config.BearerToken)
	}
	response, err := t.client.Do(request)
	if err != nil {
		return Result{Content: "approved HTTP request failed", IsError: true, Classification: "network"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, t.config.MaxResultBytes+1))
	if err != nil {
		return Result{Content: "approved HTTP response could not be read", IsError: true, Classification: "network", Status: response.StatusCode}
	}
	if int64(len(body)) > t.config.MaxResultBytes {
		return Result{Content: string(body[:t.config.MaxResultBytes]), IsError: true, Classification: "truncated", Status: response.StatusCode}
	}
	return Result{Content: string(body), IsError: response.StatusCode < 200 || response.StatusCode >= 300, Classification: "untrusted", Status: response.StatusCode}
}

func (t *HTTPTool) validateURL(target *url.URL) error {
	if target.Scheme != "https" || target.User != nil || target.Hostname() == "" || target.Fragment != "" {
		return fmt.Errorf("HTTPS URL without userinfo or fragment required")
	}
	if _, ok := t.hosts[strings.ToLower(target.Hostname())]; !ok {
		return fmt.Errorf("host not allowed")
	}
	if len(t.config.PathPrefixes) > 0 {
		allowed := false
		escaped := strings.ToLower(target.EscapedPath())
		if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || path.Clean(target.Path) != target.Path {
			return fmt.Errorf("ambiguous path not allowed")
		}
		for _, prefix := range t.config.PathPrefixes {
			base := strings.TrimSuffix(prefix, "/")
			if target.EscapedPath() == base || strings.HasPrefix(target.EscapedPath(), base+"/") {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("path not allowed")
		}
	}
	return nil
}

func (t *HTTPTool) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, ok := t.hosts[strings.ToLower(host)]; !ok {
		return nil, fmt.Errorf("dial host not allowed")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, addressValue := range addresses {
		if !t.config.AllowPrivate && unsafeAddress(addressValue) {
			continue
		}
		return (&net.Dialer{Timeout: t.config.Timeout}).DialContext(ctx, network, net.JoinHostPort(addressValue.String(), port))
	}
	return nil, fmt.Errorf("host resolved only to blocked addresses")
}

func unsafeAddress(address netip.Addr) bool {
	return !address.IsValid() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast()
}
