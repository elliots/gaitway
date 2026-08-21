package banner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const defaultMaxJSONBytes = 8 << 20
const deferActivationHeader = "X-Gaitway-Defer-Activation"

// Transformer injects a static marker into the first text-bearing response of
// a claimed Claude session. All other responses remain untouched.
type Transformer struct {
	message       string
	registry      *Registry
	maxLineBytes  int
	maxFrameBytes int
	maxJSONBytes  int
}

func NewTransformer(message string, registry *Registry, maxLineBytes, maxFrameBytes int) *Transformer {
	return &Transformer{
		message:       message,
		registry:      registry,
		maxLineBytes:  maxLineBytes,
		maxFrameBytes: maxFrameBytes,
		maxJSONBytes:  defaultMaxJSONBytes,
	}
}

func (t *Transformer) Enabled() bool { return t != nil && t.message != "" && t.registry != nil }

func (t *Transformer) Claim(session string) bool {
	return t.Enabled() && t.registry.Claim(session)
}

func (t *Transformer) Release(session string) {
	if t != nil && t.registry != nil {
		t.registry.Release(session)
	}
}

// TransformResponse mutates only eligible successful identity-encoded bodies.
// It returns true when the response is or may be transformed asynchronously.
func (t *Transformer) TransformResponse(resp *http.Response, session string) bool {
	deferActivation := resp.Header.Get(deferActivationHeader) == "1"
	resp.Header.Del(deferActivationHeader)
	if deferActivation {
		t.Release(session)
		return false
	}
	if !t.Enabled() || session == "" || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Release(session)
		return false
	}
	encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		t.Release(session)
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mediaType {
	case "text/event-stream":
		resp.Body = t.streamingBody(resp.Body, session)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return true
	case "application/json":
		return t.transformJSON(resp, session)
	default:
		t.Release(session)
		return false
	}
}

func (t *Transformer) transformJSON(resp *http.Response, session string) bool {
	limited := io.LimitReader(resp.Body, int64(t.maxJSONBytes)+1)
	body, err := io.ReadAll(limited)
	_ = resp.Body.Close()
	if err != nil || len(body) > t.maxJSONBytes {
		// The original stream cannot be reconstructed after an I/O error. For an
		// oversized well-formed body, preserve the bytes already read and fail the
		// response explicitly rather than claiming successful activation.
		t.Release(session)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
		return false
	}
	changed, ok := prependFirstText(body, t.message+"\n\n")
	if !ok {
		t.Release(session)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
		return false
	}
	t.registry.MarkEmitted(session)
	resp.Body = io.NopCloser(bytes.NewReader(changed))
	resp.ContentLength = int64(len(changed))
	resp.Header.Set("Content-Length", fmt.Sprint(len(changed)))
	return true
}

func (t *Transformer) streamingBody(src io.ReadCloser, session string) io.ReadCloser {
	reader, writer := io.Pipe()
	go func() {
		emitted := false
		err := t.copySSE(writer, src, func() {
			emitted = true
			t.registry.MarkEmitted(session)
		})
		_ = src.Close()
		if !emitted {
			t.registry.Release(session)
		}
		_ = writer.CloseWithError(err)
	}()
	return &pipeBody{PipeReader: reader, source: src}
}

type pipeBody struct {
	*io.PipeReader
	source io.Closer
}

func (b *pipeBody) Close() error {
	_ = b.source.Close()
	return b.PipeReader.Close()
}

func (t *Transformer) copySSE(dst io.Writer, src io.Reader, onEmit func()) error {
	reader := bufio.NewReaderSize(src, 64<<10)
	for {
		frame, err := readFrame(reader, t.maxLineBytes, t.maxFrameBytes)
		if len(frame) > 0 {
			if _, writeErr := dst.Write(frame); writeErr != nil {
				return writeErr
			}
			if index, ok := firstTextBlockStart(frame); ok {
				injected, marshalErr := activationFrame(index, t.message+"\n\n", lineEnding(frame))
				if marshalErr != nil {
					return marshalErr
				}
				onEmit()
				if _, writeErr := dst.Write(injected); writeErr != nil {
					return writeErr
				}
				_, copyErr := io.Copy(dst, reader)
				return copyErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func readFrame(reader *bufio.Reader, maxLine, maxFrame int) ([]byte, error) {
	var frame []byte
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > maxLine || len(frame)+len(line) > maxFrame {
			return append(frame, line...), fmt.Errorf("SSE frame exceeds configured limit")
		}
		frame = append(frame, line...)
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			return frame, err
		}
		if err != nil {
			return frame, err
		}
	}
}

func firstTextBlockStart(frame []byte) (int, bool) {
	var data []byte
	for _, line := range bytes.Split(frame, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, []byte("data:")) {
			part := bytes.TrimPrefix(line, []byte("data:"))
			part = bytes.TrimPrefix(part, []byte(" "))
			if data != nil {
				data = append(data, '\n')
			}
			data = append(data, part...)
		}
	}
	if len(data) == 0 {
		return 0, false
	}
	var event struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
		} `json:"content_block"`
	}
	if json.Unmarshal(data, &event) != nil {
		return 0, false
	}
	return event.Index, event.Type == "content_block_start" && event.ContentBlock.Type == "text"
}

func activationFrame(index int, text, eol string) ([]byte, error) {
	event := struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
		Delta struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"delta"`
	}{Type: "content_block_delta", Index: index}
	event.Delta.Type = "text_delta"
	event.Delta.Text = text
	data, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return []byte("event: content_block_delta" + eol + "data: " + string(data) + eol + eol), nil
}

func lineEnding(frame []byte) string {
	if bytes.Contains(frame, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

type jsonSpan struct{ start, end int }

func prependFirstText(input []byte, prefix string) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, false
		}
		if key != "content" {
			if err := skipJSONValue(dec); err != nil {
				return nil, false
			}
			continue
		}
		span, text, ok := findTextSpan(dec, input)
		if !ok {
			return nil, false
		}
		replacement, _ := json.Marshal(prefix + text)
		out := make([]byte, 0, len(input)+len(replacement)-(span.end-span.start))
		out = append(out, input[:span.start]...)
		out = append(out, replacement...)
		out = append(out, input[span.end:]...)
		return out, true
	}
	return nil, false
}

func findTextSpan(dec *json.Decoder, input []byte) (jsonSpan, string, bool) {
	token, err := dec.Token()
	if err != nil || token != json.Delim('[') {
		return jsonSpan{}, "", false
	}
	for dec.More() {
		token, err = dec.Token()
		if err != nil || token != json.Delim('{') {
			return jsonSpan{}, "", false
		}
		var typ, text string
		var span jsonSpan
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return jsonSpan{}, "", false
			}
			before := int(dec.InputOffset())
			value, err := dec.Token()
			if err != nil {
				return jsonSpan{}, "", false
			}
			after := int(dec.InputOffset())
			switch key {
			case "type":
				typ, _ = value.(string)
			case "text":
				text, _ = value.(string)
				segment := input[before:after]
				quote := bytes.IndexByte(segment, '"')
				if quote >= 0 {
					span = jsonSpan{start: before + quote, end: after}
				}
			default:
				if delim, ok := value.(json.Delim); ok && (delim == '{' || delim == '[') {
					if err := skipJSONContainer(dec, delim); err != nil {
						return jsonSpan{}, "", false
					}
				}
			}
		}
		if _, err := dec.Token(); err != nil {
			return jsonSpan{}, "", false
		}
		if typ == "text" && span.end > span.start {
			return span, text, true
		}
	}
	return jsonSpan{}, "", false
}

func skipJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); ok && (delim == '{' || delim == '[') {
		return skipJSONContainer(dec, delim)
	}
	return nil
}

func skipJSONContainer(dec *json.Decoder, open json.Delim) error {
	close := json.Delim('}')
	if open == '[' {
		close = ']'
	}
	for dec.More() {
		if err := skipJSONValue(dec); err != nil {
			return err
		}
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != close {
		return fmt.Errorf("unexpected JSON delimiter %v", token)
	}
	return nil
}
