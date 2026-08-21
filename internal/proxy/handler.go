package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"gaitway/internal/banner"
)

type Config struct {
	Upstream        *url.URL
	Transport       http.RoundTripper
	Banner          *banner.Transformer
	MaxRequestBytes int64
	MaxSessionBytes int
	Logger          *slog.Logger
	Hooks           Hooks
}

type Hooks interface {
	Prepare(http.ResponseWriter, *http.Request) (*http.Request, bool)
	WrapResponse(*http.Request, *http.Response)
	Fail(*http.Request, error)
}

type activationEligibility interface {
	ActivationEligible(*http.Request) bool
}

type claimKey struct{}

func NewHandler(config Config) (http.Handler, error) {
	if config.Upstream == nil || config.Upstream.Scheme == "" || config.Upstream.Host == "" {
		return nil, fmt.Errorf("upstream URL is required")
	}
	if config.Transport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableCompression = true
		transport.DisableKeepAlives = true
		config.Transport = transport
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = 32 << 20
	}
	if config.MaxSessionBytes <= 0 {
		config.MaxSessionBytes = 256
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	reverse := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(config.Upstream)
			request.Out.URL.RawQuery = request.In.URL.RawQuery
			request.Out.GetBody = nil
			// The activation seam cannot safely mutate a compressed body. Ask the
			// upstream for identity encoding only on the one claimed response;
			// passive requests retain the client's original encoding negotiation.
			if claim, _ := request.In.Context().Value(claimKey{}).(string); claim != "" {
				request.Out.Header.Del("Accept-Encoding")
			}
		},
		Transport:     config.Transport,
		FlushInterval: -1,
		ModifyResponse: func(response *http.Response) error {
			claim, _ := response.Request.Context().Value(claimKey{}).(string)
			if claim != "" {
				config.Banner.TransformResponse(response, claim)
			}
			// Never expose coordinator-only response metadata to clients, including
			// sessions whose activation marker was already emitted.
			response.Header.Del("X-Gaitway-Defer-Activation")
			if config.Hooks != nil {
				config.Hooks.WrapResponse(response.Request, response)
			}
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
			claim, _ := request.Context().Value(claimKey{}).(string)
			if claim != "" {
				config.Banner.Release(claim)
			}
			if config.Hooks != nil {
				config.Hooks.Fail(request, err)
			}
			if errors.Is(err, context.Canceled) || errors.Is(request.Context().Err(), context.Canceled) {
				return
			}
			config.Logger.Error("upstream request failed", "route", routeName(request.URL.Path))
			http.Error(writer, "bad gateway", http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodHead && request.URL.Path == "/api/hello" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if request.URL.Path != "/v1/messages" && request.URL.Path != "/v1/messages/count_tokens" {
			http.NotFound(writer, request)
			return
		}
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, config.MaxRequestBytes)
		if config.Hooks != nil {
			var ok bool
			request, ok = config.Hooks.Prepare(writer, request)
			if !ok {
				return
			}
		}
		if request.URL.Path == "/v1/messages" && config.Banner != nil {
			eligible := true
			if classifier, ok := config.Hooks.(activationEligibility); ok {
				eligible = classifier.ActivationEligible(request)
			}
			if session, ok := safeSession(request.Header.Values("x-claude-code-session-id"), config.MaxSessionBytes); eligible && ok && config.Banner.Claim(session) {
				request = request.WithContext(context.WithValue(request.Context(), claimKey{}, session))
			}
		}
		started := time.Now()
		config.Logger.Info("request accepted", "route", routeName(request.URL.Path))
		reverse.ServeHTTP(writer, request)
		config.Logger.Info("request finished", "route", routeName(request.URL.Path), "duration_ms", time.Since(started).Milliseconds())
	}), nil
}

func safeSession(values []string, max int) (string, bool) {
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > max {
		return "", false
	}
	for _, char := range []byte(values[0]) {
		if char < 0x21 || char > 0x7e {
			return "", false
		}
	}
	return values[0], true
}

func routeName(path string) string {
	return strings.TrimPrefix(path, "/v1/")
}
