package telemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestDisabledTelemetryIsNoop(t *testing.T) {
	recorder, logger, shutdown, err := New(context.Background(), "", slog.NewTextHandler(io.Discard, nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx := recorder.Begin(context.Background(), "messages")
	recorder.Finish(ctx, "completed", 200, time.Millisecond)
	logger.Info("safe", "route", "messages")
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
