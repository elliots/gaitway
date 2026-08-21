package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
	"gaitway/internal/banner"
	"gaitway/internal/control"
	"gaitway/internal/identity"
	"gaitway/internal/plugin"
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
	dataDir          string
	secretAction     plugin.Action
	approvedModels   []string
	budgetWindow     time.Duration
	budgetWarning    int64
	budgetHard       int64
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
	objects, err := archive.NewFilesystem(filepath.Join(settings.dataDir, "content"))
	if err != nil {
		logger.Error("cannot open content archive", "error", err)
		os.Exit(2)
	}
	events, err := audit.NewJSONLStore(filepath.Join(settings.dataDir, "audit.jsonl"))
	if err != nil {
		logger.Error("cannot open audit store", "error", err)
		os.Exit(2)
	}
	identityKey, err := loadOrCreateKey(filepath.Join(settings.dataDir, "identity-hmac.key"))
	if err != nil {
		logger.Error("cannot load identity key", "error", err)
		os.Exit(2)
	}
	resolver, err := identity.NewResolver(identityKey)
	if err != nil {
		logger.Error("cannot create identity resolver", "error", err)
		os.Exit(2)
	}
	policies, err := plugin.NewEngine(100*time.Millisecond,
		plugin.NewSecretScanner(settings.secretAction),
		plugin.NewModelPolicy(settings.approvedModels),
		plugin.NewBudgetPolicy(settings.budgetWindow, settings.budgetWarning, settings.budgetHard),
	)
	if err != nil {
		logger.Error("cannot create policy engine", "error", err)
		os.Exit(2)
	}
	controller := control.NewService(objects, events, resolver, policies, settings.maxRequestBytes)
	handler, err := proxy.NewHandler(proxy.Config{
		Upstream:        settings.upstream,
		Banner:          transformer,
		MaxRequestBytes: settings.maxRequestBytes,
		MaxSessionBytes: settings.maxSessionBytes,
		Logger:          logger,
		Hooks:           controller,
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
		dataDir:          envOr("GAITWAY_DATA_DIR", "./data"),
		secretAction:     plugin.Action(envOr("GAITWAY_SECRET_ACTION", "reject")),
		approvedModels:   splitList(os.Getenv("GAITWAY_APPROVED_MODELS")),
		budgetWindow:     time.Hour,
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
	if raw := os.Getenv("GAITWAY_BUDGET_WINDOW"); raw != "" {
		if result.budgetWindow, err = time.ParseDuration(raw); err != nil || result.budgetWindow <= 0 {
			return config{}, fmt.Errorf("GAITWAY_BUDGET_WINDOW must be a positive duration")
		}
	}
	if result.budgetWarning, err = nonNegativeInt64("GAITWAY_BUDGET_WARNING_UNITS", 0); err != nil {
		return config{}, err
	}
	if result.budgetHard, err = nonNegativeInt64("GAITWAY_BUDGET_HARD_UNITS", 0); err != nil {
		return config{}, err
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

func nonNegativeInt64(name string, fallback int64) (int64, error) {
	raw, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return value, nil
}

func splitList(raw string) []string {
	var result []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func loadOrCreateKey(path string) ([]byte, error) {
	if key, err := os.ReadFile(path); err == nil {
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".identity-key-*")
	if err != nil {
		return nil, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(key); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		if existing, readErr := os.ReadFile(path); readErr == nil {
			return existing, nil
		}
		return nil, err
	}
	return key, nil
}
