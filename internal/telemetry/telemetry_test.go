package telemetry

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestDisabledTelemetryIsNoop(t *testing.T) {
	recorder, logger, shutdown, err := New(t.Context(), "", slog.NewTextHandler(io.Discard, nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx := recorder.Begin(t.Context(), "messages")
	recorder.Finish(ctx, "completed", 200, time.Millisecond)
	logger.Info("safe", "route", "messages")
	if err := shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}
