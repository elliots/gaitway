package banner

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

const testStream = "event: message_start\n" +
	"data: {\"type\":\"message_start\",\"message\":{}}\n\n" +
	"event: content_block_start\n" +
	"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\n" +
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n" +
	"event: message_stop\n" +
	"data: {\"type\":\"message_stop\"}\n\n"

func TestStreamingActivation(t *testing.T) {
	registry := NewRegistry(10)
	transformer := NewTransformer("*** Gaitway Active ***", registry, 1<<20, 8<<20)
	if !transformer.Claim("session") {
		t.Fatal("claim failed")
	}
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(testStream)),
	}
	if !transformer.TransformResponse(response, "session") {
		t.Fatal("response was not transformed")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	marker := `"text":"*** Gaitway Active ***\n\n"`
	if strings.Count(text, marker) != 1 {
		t.Fatalf("marker count = %d\n%s", strings.Count(text, marker), text)
	}
	if !strings.Contains(text, `"text":"hello"`) {
		t.Fatal("original delta missing")
	}
	if transformer.Claim("session") {
		t.Fatal("session activated twice")
	}
}

func TestNonStreamingActivationPreservesSurroundingBytes(t *testing.T) {
	registry := NewRegistry(10)
	transformer := NewTransformer("active", registry, 1<<20, 8<<20)
	if !transformer.Claim("session") {
		t.Fatal("claim failed")
	}
	original := "{ \"id\" : \"m1\", \"content\" : [ { \"type\" : \"text\", \"text\" : \"hello\", \"future\" : {\"x\":1} } ], \"unknown\":true }"
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(original)),
	}
	if !transformer.TransformResponse(response, "session") {
		t.Fatal("response was not transformed")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(original, `"hello"`, `"active\n\nhello"`, 1)
	if string(body) != want {
		t.Fatalf("unexpected body\n got: %s\nwant: %s", body, want)
	}
}

func TestToolOnlyResponseReleasesClaim(t *testing.T) {
	registry := NewRegistry(10)
	transformer := NewTransformer("active", registry, 1<<20, 8<<20)
	if !transformer.Claim("session") {
		t.Fatal("claim failed")
	}
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"content":[{"type":"tool_use","id":"x"}]}`)),
	}
	if transformer.TransformResponse(response, "session") {
		t.Fatal("tool-only response was transformed")
	}
	if !transformer.Claim("session") {
		t.Fatal("tool-only response did not release claim")
	}
}

func TestDeferredResponseReleasesClaimWithoutLeakingHeader(t *testing.T) {
	registry := NewRegistry(10)
	transformer := NewTransformer("active", registry, 1<<20, 8<<20)
	if !transformer.Claim("session") {
		t.Fatal("claim failed")
	}
	response := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":        {"text/event-stream"},
			deferActivationHeader: {"1"},
		},
		Body: io.NopCloser(strings.NewReader(testStream)),
	}
	if transformer.TransformResponse(response, "session") {
		t.Fatal("deferred response was transformed")
	}
	if response.Header.Get(deferActivationHeader) != "" {
		t.Fatal("internal activation header leaked")
	}
	if !transformer.Claim("session") {
		t.Fatal("deferred response did not release claim")
	}
}
