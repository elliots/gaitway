package main

import (
	"context"
	"crypto/rand"
	"errors"
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
	"gaitway/internal/dashboard"
	"gaitway/internal/gatewaytool"
	"gaitway/internal/identity"
	"gaitway/internal/plugin"
	postgresstore "gaitway/internal/postgres"
	"gaitway/internal/proxy"
	"gaitway/internal/telemetry"
)

const defaultActivation = "Gaitway Active"

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
	cardAction       plugin.Action
	testCards        []string
	approvedModels   []string
	blockedModels    []string
	budgetWindow     time.Duration
	budgetWarning    int64
	budgetHard       int64
	budgetMessage    string
	adminAddr        string
	databaseURL      string
	otelEndpoint     string
	toolsEnabled     bool
	toolHosts        []string
	toolPaths        []string
	toolBearerToken  string
	toolAllowPrivate bool
	toolTimeout      time.Duration
	toolMaxBytes     int64
	archiveBackend   string
	s3Endpoint       string
	s3Region         string
	s3Bucket         string
	s3Prefix         string
	s3AccessKey      string
	s3SecretKey      string
	s3SessionToken   string
	s3AllowHTTP      bool
	s3CreateBucket   bool
	oauthProfile     bool
}

func main() {
	localLogs := slog.NewJSONHandler(os.Stderr, nil)
	if err := run(localLogs); err != nil {
		slog.New(localLogs).Error("gaitway stopped", "error", err)
		os.Exit(1)
	}
}

func run(localLogs slog.Handler) (runErr error) {
	settings, err := loadConfig()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	telemetryRecorder, telemetryLogger, shutdownTelemetry, err := telemetry.New(context.Background(), settings.otelEndpoint, localLogs)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	logger := telemetryLogger
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, shutdownTelemetry(ctx))
	}()

	registry := banner.NewRegistry(settings.maxSessions)
	transformer := banner.NewTransformer(settings.activation, registry, settings.maxSSELineBytes, settings.maxSSEFrameBytes)
	var objects archive.Store
	if settings.archiveBackend == "s3" {
		objects, err = archive.NewS3(context.Background(), archive.S3Config{
			Endpoint: settings.s3Endpoint, Region: settings.s3Region, Bucket: settings.s3Bucket, Prefix: settings.s3Prefix,
			AccessKey: settings.s3AccessKey, SecretKey: settings.s3SecretKey, SessionToken: settings.s3SessionToken,
			AllowHTTP: settings.s3AllowHTTP, CreateBucket: settings.s3CreateBucket,
		})
	} else {
		objects, err = archive.NewFilesystem(filepath.Join(settings.dataDir, "content"))
	}
	if err != nil {
		return fmt.Errorf("open content archive: %w", err)
	}
	var events audit.Store
	var closeEvents func()
	if settings.databaseURL != "" {
		postgresEvents, openErr := postgresstore.New(context.Background(), settings.databaseURL)
		if openErr != nil {
			return fmt.Errorf("open postgres audit store: %w", openErr)
		}
		events = postgresEvents
		closeEvents = postgresEvents.Close
	} else {
		fileEvents, openErr := audit.NewJSONLStore(filepath.Join(settings.dataDir, "audit.jsonl"))
		if openErr != nil {
			return fmt.Errorf("open audit store: %w", openErr)
		}
		events = fileEvents
		closeEvents = func() {}
	}
	defer closeEvents()
	identityKey, err := loadOrCreateKey(filepath.Join(settings.dataDir, "identity-hmac.key"))
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}
	resolver, err := identity.NewResolver(identityKey)
	if err != nil {
		return fmt.Errorf("create identity resolver: %w", err)
	}
	if err := restoreProfiles(context.Background(), events, resolver); err != nil {
		return fmt.Errorf("restore Anthropic identity mappings: %w", err)
	}
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	defer baseTransport.CloseIdleConnections()
	baseTransport.DisableCompression = true
	baseTransport.DisableKeepAlives = true
	policies, err := plugin.NewEngine(100*time.Millisecond,
		plugin.NewSecretScanner(settings.secretAction),
		plugin.NewCardScanner(settings.cardAction, settings.testCards),
		plugin.NewModelPolicy(settings.approvedModels, settings.blockedModels),
		plugin.NewBudgetPolicy(settings.budgetWindow, settings.budgetWarning, settings.budgetHard, settings.budgetMessage),
	)
	if err != nil {
		return fmt.Errorf("create policy engine: %w", err)
	}
	controller := control.NewService(objects, events, resolver, policies, settings.maxRequestBytes, telemetryRecorder)
	controller.SetBanner(transformer)
	if settings.oauthProfile {
		profiles, profileErr := identity.NewProfileLookup(settings.upstream, baseTransport, resolver, events)
		if profileErr != nil {
			return fmt.Errorf("create Anthropic identity lookup: %w", profileErr)
		}
		controller.SetProfileLookup(profiles)
	}
	admin, err := dashboard.New(events, objects)
	if err != nil {
		return fmt.Errorf("create dashboard: %w", err)
	}
	var upstreamTransport http.RoundTripper = baseTransport
	if settings.toolsEnabled {
		httpTool := gatewaytool.NewHTTPTool(gatewaytool.HTTPConfig{
			AllowedHosts: settings.toolHosts, PathPrefixes: settings.toolPaths, BearerToken: settings.toolBearerToken,
			AllowPrivate: settings.toolAllowPrivate, Timeout: settings.toolTimeout, MaxResultBytes: settings.toolMaxBytes,
		})
		toolRegistry, registryErr := gatewaytool.NewRegistry(httpTool)
		if registryErr != nil {
			return fmt.Errorf("register gateway tools: %w", registryErr)
		}
		toolKey, keyErr := loadOrCreateKey(filepath.Join(settings.dataDir, "gateway-tool-hmac.key"))
		if keyErr != nil {
			return fmt.Errorf("load gateway tool fingerprint key: %w", keyErr)
		}
		toolFingerprinter, fingerprintErr := gatewaytool.NewFingerprinter(toolKey)
		if fingerprintErr != nil {
			return fmt.Errorf("create gateway tool fingerprinter: %w", fingerprintErr)
		}
		coordinator, coordinatorErr := gatewaytool.NewCoordinator(gatewaytool.CoordinatorConfig{
			Next: upstreamTransport, Registry: toolRegistry, Fingerprinter: toolFingerprinter, MaxBody: settings.maxRequestBytes, Observer: controller,
		})
		if coordinatorErr != nil {
			return fmt.Errorf("create gateway tool coordinator: %w", coordinatorErr)
		}
		upstreamTransport = coordinator
	}
	handler, err := proxy.NewHandler(proxy.Config{
		Upstream:        settings.upstream,
		Transport:       upstreamTransport,
		Banner:          transformer,
		MaxRequestBytes: settings.maxRequestBytes,
		MaxSessionBytes: settings.maxSessionBytes,
		Logger:          logger,
		Hooks:           controller,
	})
	if err != nil {
		return fmt.Errorf("create gateway: %w", err)
	}

	listener, err := net.Listen("tcp", settings.listenAddr)
	if err != nil {
		return fmt.Errorf("listen for gateway: %w", err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	adminServer := &http.Server{
		Handler:           admin.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       time.Minute,
	}
	adminListener, err := net.Listen("tcp", settings.adminAddr)
	if err != nil {
		return fmt.Errorf("listen for dashboard: %w", err)
	}
	defer adminListener.Close()
	logger.Info("gaitway ready", "address", listener.Addr().String(), "activation", settings.activation != "")
	logger.Warn("dashboard has no application authentication", "address", adminListener.Addr().String())

	stopping, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErrors := make(chan error, 2)
	serve := func(name string, server *http.Server, listener net.Listener) {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- fmt.Errorf("serve %s: %w", name, err)
		}
	}
	go serve("gateway", server, listener)
	go serve("dashboard", adminServer, adminListener)

	var serveErr error
	select {
	case <-stopping.Done():
	case serveErr = <-serveErrors:
		stop()
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownErr := errors.Join(server.Shutdown(shutdownContext), adminServer.Shutdown(shutdownContext))
	return errors.Join(serveErr, shutdownErr)
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
		cardAction:       plugin.Action(envOr("GAITWAY_CARD_ACTION", "redact")),
		testCards:        plugin.DefaultTestCards,
		approvedModels:   splitList(os.Getenv("GAITWAY_APPROVED_MODELS")),
		blockedModels:    splitList(envOr("GAITWAY_BLOCKED_MODEL_FAMILIES", "haiku")),
		budgetWindow:     4 * time.Hour,
		budgetMessage:    envOr("GAITWAY_BUDGET_LIMIT_MESSAGE", "Gaitway usage limit reached"),
		adminAddr:        envOr("GAITWAY_ADMIN_ADDR", "127.0.0.1:8081"),
		databaseURL:      os.Getenv("DATABASE_URL"),
		otelEndpoint:     os.Getenv("GAITWAY_OTEL_ENDPOINT"),
		toolHosts:        splitList(os.Getenv("GAITWAY_HTTP_TOOL_HOSTS")),
		toolPaths:        splitList(os.Getenv("GAITWAY_HTTP_TOOL_PATHS")),
		toolBearerToken:  os.Getenv("GAITWAY_HTTP_TOOL_BEARER_TOKEN"),
		toolTimeout:      10 * time.Second,
		toolMaxBytes:     1 << 20,
		archiveBackend:   envOr("GAITWAY_ARCHIVE_BACKEND", "filesystem"),
		s3Endpoint:       os.Getenv("GAITWAY_S3_ENDPOINT"),
		s3Region:         os.Getenv("GAITWAY_S3_REGION"),
		s3Bucket:         os.Getenv("GAITWAY_S3_BUCKET"),
		s3Prefix:         os.Getenv("GAITWAY_S3_PREFIX"),
		s3AccessKey:      os.Getenv("GAITWAY_S3_ACCESS_KEY"),
		s3SecretKey:      os.Getenv("GAITWAY_S3_SECRET_KEY"),
		s3SessionToken:   os.Getenv("GAITWAY_S3_SESSION_TOKEN"),
		oauthProfile:     true,
	}
	var boolErr error
	if result.toolsEnabled, boolErr = envBool("GAITWAY_TOOLS_ENABLED", false); boolErr != nil {
		return config{}, boolErr
	}
	if result.toolAllowPrivate, boolErr = envBool("GAITWAY_HTTP_TOOL_ALLOW_PRIVATE", false); boolErr != nil {
		return config{}, boolErr
	}
	if result.s3AllowHTTP, boolErr = envBool("GAITWAY_S3_ALLOW_HTTP", false); boolErr != nil {
		return config{}, boolErr
	}
	if result.s3CreateBucket, boolErr = envBool("GAITWAY_S3_CREATE_BUCKET", false); boolErr != nil {
		return config{}, boolErr
	}
	if result.oauthProfile, boolErr = envBool("GAITWAY_OAUTH_PROFILE", true); boolErr != nil {
		return config{}, boolErr
	}
	if raw, exists := os.LookupEnv("GAITWAY_CARD_TEST_NUMBERS"); exists {
		result.testCards = splitList(raw)
	}
	if result.archiveBackend != "filesystem" && result.archiveBackend != "s3" {
		return config{}, fmt.Errorf("GAITWAY_ARCHIVE_BACKEND must be filesystem or s3")
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

	if result.maxRequestBytes, err = positiveInt64("GAITWAY_MAX_REQUEST_BYTES", result.maxRequestBytes); err != nil {
		return config{}, err
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
	if raw := os.Getenv("GAITWAY_HTTP_TOOL_TIMEOUT"); raw != "" {
		if result.toolTimeout, err = time.ParseDuration(raw); err != nil || result.toolTimeout <= 0 {
			return config{}, fmt.Errorf("GAITWAY_HTTP_TOOL_TIMEOUT must be a positive duration")
		}
	}
	if result.toolMaxBytes, err = positiveInt64("GAITWAY_HTTP_TOOL_MAX_RESULT_BYTES", result.toolMaxBytes); err != nil {
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
	for item := range strings.SplitSeq(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func restoreProfiles(ctx context.Context, events audit.Store, resolver *identity.Resolver) error {
	recent, err := events.List(ctx, 1000)
	if err != nil {
		return err
	}
	for _, event := range recent {
		if event.AccountID != "" && event.OrganizationID != "" && !resolver.HasProfile(event.Principal) {
			resolver.RecordProfile(event.Principal, identity.Profile{
				AccountID: event.AccountID, OrganizationID: event.OrganizationID, Email: event.Email,
				DisplayName: event.DisplayName, FullName: event.FullName,
			})
		}
	}
	return nil
}

func envBool(name string, fallback bool) (bool, error) {
	raw, exists := os.LookupEnv(name)
	if !exists {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return value, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if key, err := os.ReadFile(path); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
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
