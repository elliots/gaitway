package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gaitway/internal/banner"
	"gaitway/internal/proxy"
)

const defaultActivation = "*** Gaitway Active ***"

type config struct {
	listenAddr       string
	upstream         *url.URL
	activation       string
	maxRequestBytes  int64
	maxSessionBytes  int
	maxSessions      int
	maxSSELineBytes  int
	maxSSEFrameBytes int
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	settings, err := loadConfig()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	registry := banner.NewRegistry(settings.maxSessions)
	transformer := banner.NewTransformer(settings.activation, registry, settings.maxSSELineBytes, settings.maxSSEFrameBytes)
	handler, err := proxy.NewHandler(proxy.Config{
		Upstream:        settings.upstream,
		Banner:          transformer,
		MaxRequestBytes: settings.maxRequestBytes,
		MaxSessionBytes: settings.maxSessionBytes,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("cannot create gateway", "error", err)
		os.Exit(2)
	}

	listener, err := net.Listen("tcp", settings.listenAddr)
	if err != nil {
		logger.Error("cannot listen", "error", err)
		os.Exit(2)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	logger.Info("gaitway ready", "address", listener.Addr().String(), "activation", settings.activation != "")

	stopping, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-stopping.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		logger.Error("gateway stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	result := config{
		listenAddr:       envOr("GAITWAY_LISTEN_ADDR", "127.0.0.1:8080"),
		maxRequestBytes:  32 << 20,
		maxSessionBytes:  256,
		maxSessions:      10_000,
		maxSSELineBytes:  1 << 20,
		maxSSEFrameBytes: 8 << 20,
	}
	if activation, exists := os.LookupEnv("GAITWAY_ACTIVATION_MESSAGE"); exists {
		result.activation = activation
	} else {
		result.activation = defaultActivation
	}

	upstream, err := url.Parse(envOr("GAITWAY_UPSTREAM_URL", "https://api.anthropic.com"))
	if err != nil || upstream.Scheme != "https" || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		return config{}, fmt.Errorf("GAITWAY_UPSTREAM_URL must be an absolute HTTPS origin without userinfo, query, or fragment")
	}
	result.upstream = upstream

	numbers := []struct {
		name   string
		target *int64
		value  int64
	}{
		{"GAITWAY_MAX_REQUEST_BYTES", &result.maxRequestBytes, result.maxRequestBytes},
	}
	for _, number := range numbers {
		parsed, err := positiveInt64(number.name, number.value)
		if err != nil {
			return config{}, err
		}
		*number.target = parsed
	}
	var intErr error
	if result.maxSessionBytes, intErr = positiveInt("GAITWAY_MAX_SESSION_ID_BYTES", result.maxSessionBytes); intErr != nil {
		return config{}, intErr
	}
	if result.maxSessions, intErr = positiveInt("GAITWAY_MAX_ACTIVATION_SESSIONS", result.maxSessions); intErr != nil {
		return config{}, intErr
	}
	if result.maxSSELineBytes, intErr = positiveInt("GAITWAY_MAX_SSE_LINE_BYTES", result.maxSSELineBytes); intErr != nil {
		return config{}, intErr
	}
	if result.maxSSEFrameBytes, intErr = positiveInt("GAITWAY_MAX_SSE_FRAME_BYTES", result.maxSSEFrameBytes); intErr != nil {
		return config{}, intErr
	}
	return result, nil
}

func envOr(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func positiveInt(name string, fallback int) (int, error) {
	value, err := positiveInt64(name, int64(fallback))
	return int(value), err
}

func positiveInt64(name string, fallback int64) (int64, error) {
	raw, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}
