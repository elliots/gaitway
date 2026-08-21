package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

type Recorder struct {
	tracer   trace.Tracer
	requests metric.Int64Counter
	latency  metric.Int64Histogram
}

type Shutdown func(context.Context) error

func New(ctx context.Context, endpoint string, local slog.Handler) (*Recorder, *slog.Logger, Shutdown, error) {
	if strings.TrimSpace(endpoint) == "" {
		return &Recorder{}, slog.New(local), func(context.Context) error { return nil }, nil
	}
	base := strings.TrimRight(endpoint, "/")
	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName("gaitway")))
	if err != nil {
		return nil, nil, nil, err
	}
	traceExporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(base+"/v1/traces"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create trace exporter: %w", err)
	}
	metricExporter, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(base+"/v1/metrics"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create metric exporter: %w", err)
	}
	logExporter, err := otlploghttp.New(ctx, otlploghttp.WithEndpointURL(base+"/v1/logs"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create log exporter: %w", err)
	}

	traces := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1))),
		sdktrace.WithBatcher(traceExporter),
	)
	metrics := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(15*time.Second))),
	)
	logs := log.NewLoggerProvider(log.WithResource(res), log.WithProcessor(log.NewBatchProcessor(logExporter)))
	otel.SetTracerProvider(traces)
	otel.SetMeterProvider(metrics)
	global.SetLoggerProvider(logs)

	meter := metrics.Meter("gaitway/internal/telemetry")
	requests, err := meter.Int64Counter("gaitway.requests", metric.WithDescription("Accepted gateway requests"))
	if err != nil {
		return nil, nil, nil, err
	}
	latency, err := meter.Int64Histogram("gaitway.request.duration", metric.WithUnit("ms"), metric.WithDescription("Gateway request duration"))
	if err != nil {
		return nil, nil, nil, err
	}
	recorder := &Recorder{tracer: traces.Tracer("gaitway/internal/control"), requests: requests, latency: latency}
	logger := slog.New(fanoutHandler{handlers: []slog.Handler{local, otelslog.NewHandler("gaitway", otelslog.WithLoggerProvider(logs))}})
	shutdown := func(shutdownContext context.Context) error {
		var first error
		for _, stop := range []func(context.Context) error{logs.Shutdown, metrics.Shutdown, traces.Shutdown} {
			if err := stop(shutdownContext); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	return recorder, logger, shutdown, nil
}

func (r *Recorder) Begin(ctx context.Context, route string) context.Context {
	if r == nil || r.tracer == nil {
		return ctx
	}
	attributes := trace.WithAttributes(attribute.String("gaitway.route", route))
	ctx, _ = r.tracer.Start(ctx, "gaitway "+route, attributes)
	r.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("gaitway.route", route)))
	return ctx
}

func (r *Recorder) Finish(ctx context.Context, outcome string, status int, latency time.Duration) {
	if r == nil || r.tracer == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gaitway.outcome", outcome),
		attribute.Int("http.response.status_code", status),
	}
	r.latency.Record(ctx, latency.Milliseconds(), metric.WithAttributes(attrs...))
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
	span.End()
}

type fanoutHandler struct{ handlers []slog.Handler }

func (h fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h fanoutHandler) Handle(ctx context.Context, record slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, record.Level) {
			if err := handler.Handle(ctx, record.Clone()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	result := fanoutHandler{handlers: make([]slog.Handler, len(h.handlers))}
	for index, handler := range h.handlers {
		result.handlers[index] = handler.WithAttrs(attrs)
	}
	return result
}

func (h fanoutHandler) WithGroup(name string) slog.Handler {
	result := fanoutHandler{handlers: make([]slog.Handler, len(h.handlers))}
	for index, handler := range h.handlers {
		result.handlers[index] = handler.WithGroup(name)
	}
	return result
}
