package banner

import (
	"bytes"
	"encoding/json"
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
	transformer := NewTransformer("Claude Gateway Active", registry, 1<<20, 8<<20)
	if !transformer.Claim("session") {
		t.Fatal("claim failed")
	}
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(testStream)),
	}
	changed, err := transformer.TransformResponse(response, "session")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("response was not transformed")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	want := "event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{}}\n\n" +
		"event: content_block_start\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"> **Claude Gateway Active**\"}}\n\n" +
		"event: content_block_stop\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		strings.ReplaceAll(strings.TrimPrefix(testStream, "event: message_start\n"+"data: {\"type\":\"message_start\",\"message\":{}}\n\n"), `"index":0`, `"index":1`)
	if text != want {
		t.Fatalf("unexpected stream\n got: %s\nwant: %s", text, want)
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
	changed, err := transformer.TransformResponse(response, "session")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("response was not transformed")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(original, `[ {`, `[{"type":"text","text":"> **active**"}, {`, 1)
	if string(body) != want {
		t.Fatalf("unexpected body\n got: %s\nwant: %s", body, want)
	}
}

func TestToolOnlyResponseCarriesActivation(t *testing.T) {
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
	changed, err := transformer.TransformResponse(response, "session")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if !changed || string(body) != `{"content":[{"type":"text","text":"> **active**"},{"type":"tool_use","id":"x"}]}` {
		t.Fatalf("tool-only response not given its own activation block: %s", body)
	}
	if transformer.Claim("session") {
		t.Fatal("session activated twice")
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
	changed, err := transformer.TransformResponse(response, "session")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("deferred response was transformed")
	}
	if response.Header.Get(deferActivationHeader) != "" {
		t.Fatal("internal activation header leaked")
	}
	if !transformer.Claim("session") {
		t.Fatal("deferred response did not release claim")
	}
}

func TestNonStreamingActivationPassesThroughOverLimit(t *testing.T) {
	registry := NewRegistry(10)
	transformer := NewTransformer("active", registry, 1<<20, 8<<20)
	transformer.maxJSONBytes = 16
	if !transformer.Claim("session") {
		t.Fatal("claim failed")
	}
	original := `{"content":[{"type":"text","text":"hello"}]}`
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(original)),
	}
	changed, err := transformer.TransformResponse(response, "session")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("oversized response was reported as transformed")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != original {
		t.Fatalf("oversized response was truncated: %q", body)
	}
	if !transformer.Claim("session") {
		t.Fatal("failed transformation did not release claim")
	}
}

func TestShiftBlockIndex(t *testing.T) {
	cases := []struct{ name, frame, want string }{
		{"delta", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":9,\"delta\":{\"index\":3}}\n\n", "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":10,\"delta\":{\"index\":3}}\n\n"},
		{"index before type", "data: {\"index\": 2, \"type\": \"content_block_stop\"}\r\n\r\n", "data: {\"index\": 3, \"type\": \"content_block_stop\"}\r\n\r\n"},
		{"split data lines", "event: content_block_start\ndata: {\"type\":\"content_block_start\",\ndata: \"index\":0}\nid: 7\n\n", "event: content_block_start\ndata: {\"type\":\"content_block_start\",\n\"index\":1}\nid: 7\n\n"},
		{"message delta untouched", "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n", "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1}}\n\n"},
		{"ping untouched", ": keepalive\n\n", ": keepalive\n\n"},
		{"invalid untouched", "data: {\"type\":\"content_block_delta\",\"index\":\n\n", "data: {\"type\":\"content_block_delta\",\"index\":\n\n"},
	}
	for _, tc := range cases {
		if got := string(shiftBlockIndex([]byte(tc.frame))); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func FuzzShiftBlockIndex(f *testing.F) {
	f.Add([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":9,\"delta\":{}}\n\n"))
	f.Add([]byte("data: {\"index\": 2, \"type\": \"content_block_stop\"}\r\n\r\n"))
	f.Fuzz(func(t *testing.T, frame []byte) {
		got := shiftBlockIndex(frame)
		if bytes.Equal(got, frame) {
			return
		}
		beforeType, _, before := eventFields(framePayload(frame))
		afterType, _, after := eventFields(framePayload(got))
		if afterType != beforeType || after != before+1 {
			t.Fatalf("shift changed more than the index: %q -> %q", frame, got)
		}
	})
}

func TestStackedInsertsKeepStreamWellFormed(t *testing.T) {
	stream := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"content\":[]}}\r\n\r\n" +
		"event: ping\r\ndata: {\"type\": \"ping\"}\r\n\r\n" +
		"event: content_block_start\r\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\r\n\r\n" +
		"event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig\"}}\r\n\r\n" +
		"event: content_block_stop\r\ndata: {\"type\":\"content_block_stop\",\"index\":0}\r\n\r\n" +
		"event: content_block_start\r\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"Read\",\"input\":{}}}\r\n\r\n" +
		"event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"index\\\": 5\"}}\r\n\r\n" +
		": comment\r\n\r\n" +
		"event: content_block_stop\r\ndata: {\"type\":\"content_block_stop\",\"index\":1}\r\n\r\n" +
		"event: message_delta\r\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":9}}\r\n\r\n" +
		"event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n"
	transformer := NewTransformer("active", NewRegistry(10), 1<<20, 8<<20)
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}
	emitted := 0
	for _, text := range []string{Notice([]string{"card redacted"}), transformer.activation} {
		if _, err := transformer.InsertBlock(response, text, func(ok bool) {
			if ok {
				emitted++
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if emitted != 2 {
		t.Fatalf("emitted %d inserts", emitted)
	}
	// Replay the stream as a client would: blocks must open in order, and
	// deltas and stops must target the open block.
	var types []string
	open := -1
	for frame := range strings.SplitSeq(strings.TrimSuffix(string(body), "\r\n\r\n"), "\r\n\r\n") {
		var event struct {
			Type         string `json:"type"`
			Index        *int   `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
			} `json:"content_block"`
		}
		payload := framePayload([]byte(frame))
		if len(payload) == 0 {
			continue
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatalf("invalid event %q: %v", frame, err)
		}
		switch event.Type {
		case "content_block_start":
			if *event.Index != len(types) || open != -1 {
				t.Fatalf("block %d started out of order in:\n%s", *event.Index, body)
			}
			open = *event.Index
			types = append(types, event.ContentBlock.Type)
		case "content_block_delta", "content_block_stop":
			if *event.Index != open {
				t.Fatalf("%s for block %d while %d is open in:\n%s", event.Type, *event.Index, open, body)
			}
			if event.Type == "content_block_stop" {
				open = -1
			}
		}
	}
	if strings.Join(types, ",") != "text,text,thinking,tool_use" {
		t.Fatalf("unexpected blocks %v in:\n%s", types, body)
	}
	if !strings.Contains(string(body), `"partial_json":"{\"index\": 5"`) || !strings.Contains(string(body), "\r\n: comment\r\n") || !strings.Contains(string(body), `{"type": "ping"}`) {
		t.Fatalf("upstream bytes changed:\n%s", body)
	}
	if !strings.HasPrefix(string(body), "event: message_start\r\n") || strings.Index(string(body), "> **active**") > strings.Index(string(body), "card redacted") {
		t.Fatalf("activation is not the first block:\n%s", body)
	}
}

func TestStreamWithoutMessageStartIsNotAnnotated(t *testing.T) {
	stream := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n"
	transformer := NewTransformer("active", NewRegistry(10), 1<<20, 8<<20)
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(stream))}
	emitted := true
	if _, err := transformer.InsertBlock(response, "x", func(ok bool) { emitted = ok }); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if string(body) != stream || emitted {
		t.Fatalf("error stream changed or reported emitted: %q", body)
	}
}
