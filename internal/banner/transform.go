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
	"strconv"
	"strings"
)

const defaultMaxJSONBytes = 8 << 20
const deferActivationHeader = "X-Gaitway-Defer-Activation"

// Transformer inserts Gaitway's own text block, such as the once-per-session
// activation marker, ahead of a response's content. Upstream bytes are
// otherwise relayed unchanged apart from shifted content block indexes.
type Transformer struct {
	message       string
	activation    string
	registry      *Registry
	maxLineBytes  int
	maxFrameBytes int
	maxJSONBytes  int
}

func NewTransformer(message string, registry *Registry, maxLineBytes, maxFrameBytes int) *Transformer {
	activation := ""
	if message != "" {
		activation = Activation(message)
	}
	return &Transformer{
		message:       message,
		activation:    activation,
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
func (t *Transformer) TransformResponse(resp *http.Response, session string) (bool, error) {
	deferActivation := resp.Header.Get(deferActivationHeader) == "1"
	resp.Header.Del(deferActivationHeader)
	if deferActivation || !t.Enabled() || session == "" {
		t.Release(session)
		return false, nil
	}
	return t.InsertBlock(resp, t.activation, func(emitted bool) {
		if emitted {
			t.registry.MarkEmitted(session)
		} else {
			t.registry.Release(session)
		}
	})
}

// InsertBlock adds a text block at index 0 of a successful identity-encoded
// JSON or SSE response and shifts the upstream blocks after it. A stream
// carries the block immediately after message_start, before the model's
// output. done reports, possibly after the stream has been read, whether the
// block was written.
func (t *Transformer) InsertBlock(resp *http.Response, text string, done func(emitted bool)) (bool, error) {
	if t == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		done(false)
		return false, nil
	}
	encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		done(false)
		return false, nil
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mediaType {
	case "text/event-stream":
		resp.Body = t.streamingBody(resp.Body, text, done)
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return true, nil
	case "application/json":
		return t.transformJSON(resp, text, done)
	default:
		done(false)
		return false, nil
	}
}

func (t *Transformer) transformJSON(resp *http.Response, text string, done func(bool)) (bool, error) {
	limited := io.LimitReader(resp.Body, int64(t.maxJSONBytes)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		closeErr := resp.Body.Close()
		done(false)
		return false, fmt.Errorf("read activation response: %w", errors.Join(err, closeErr))
	}
	if len(body) > t.maxJSONBytes {
		done(false)
		source := resp.Body
		resp.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(body), source), source: source}
		return false, nil
	}
	if err := resp.Body.Close(); err != nil {
		done(false)
		return false, fmt.Errorf("close activation response: %w", err)
	}
	changed, ok := insertFirstBlock(body, text)
	if !ok {
		done(false)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
		return false, nil
	}
	done(true)
	resp.Body = io.NopCloser(bytes.NewReader(changed))
	resp.ContentLength = int64(len(changed))
	resp.Header.Set("Content-Length", fmt.Sprint(len(changed)))
	return true, nil
}

type replayBody struct {
	io.Reader
	source io.Closer
}

func (b *replayBody) Close() error { return b.source.Close() }

func (t *Transformer) streamingBody(src io.ReadCloser, text string, done func(bool)) io.ReadCloser {
	reader, writer := io.Pipe()
	go func() {
		emitted := false
		err := t.copySSE(writer, src, text, func() {
			emitted = true
			done(true)
		})
		_ = src.Close()
		if !emitted {
			done(false)
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

func (t *Transformer) copySSE(dst io.Writer, src io.Reader, text string, onEmit func()) error {
	reader := bufio.NewReaderSize(src, 64<<10)
	inserted := false
	for {
		frame, err := readFrame(reader, t.maxLineBytes, t.maxFrameBytes)
		if len(frame) > 0 {
			typ := ""
			if inserted {
				frame = shiftBlockIndex(frame)
			} else {
				typ, _, _ = eventFields(framePayload(frame))
			}
			if _, writeErr := dst.Write(frame); writeErr != nil {
				return writeErr
			}
			if typ == "message_start" {
				if _, writeErr := dst.Write(blockFrames(text, lineEnding(frame))); writeErr != nil {
					return writeErr
				}
				inserted = true
				onEmit()
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

// framePayload joins a frame's data lines as the SSE specification does.
func framePayload(frame []byte) []byte {
	var data []byte
	lines := 0
	for line := range bytes.SplitSeq(frame, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if part, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if lines > 0 {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(part, []byte(" "))...)
			lines++
		}
	}
	return data
}

// eventFields reads the top-level type and the span of a numeric index from
// an SSE data payload without decoding the rest of the event.
func eventFields(data []byte) (string, jsonSpan, int) {
	var typ string
	index, value := jsonSpan{}, -1
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return "", jsonSpan{}, -1
	}
	for dec.More() && (typ == "" || value < 0) {
		key, err := dec.Token()
		if err != nil {
			return "", jsonSpan{}, -1
		}
		switch key {
		case "type":
			token, err := dec.Token()
			if err != nil {
				return "", jsonSpan{}, -1
			}
			typ, _ = token.(string)
		case "index":
			before := int(dec.InputOffset())
			token, err := dec.Token()
			if err != nil {
				return "", jsonSpan{}, -1
			}
			number, ok := token.(json.Number)
			parsed, parseErr := strconv.Atoi(string(number))
			if !ok || parseErr != nil || parsed < 0 {
				return "", jsonSpan{}, -1
			}
			start := before + bytes.IndexAny(data[before:], "0123456789")
			index, value = jsonSpan{start: start, end: start + len(number)}, parsed
		default:
			if skipJSONValue(dec) != nil {
				return "", jsonSpan{}, -1
			}
		}
	}
	return typ, index, value
}

// shiftBlockIndex moves a content block event up one index to make room for
// the inserted block. Other frames, and frames it cannot parse, are returned
// unchanged.
func shiftBlockIndex(frame []byte) []byte {
	payload := framePayload(frame)
	if !json.Valid(payload) {
		return frame
	}
	typ, span, value := eventFields(payload)
	if value < 0 || !strings.HasPrefix(typ, "content_block_") {
		return frame
	}
	shifted := make([]byte, 0, len(payload)+1)
	shifted = append(shifted, payload[:span.start]...)
	shifted = strconv.AppendInt(shifted, int64(value+1), 10)
	shifted = append(shifted, payload[span.end:]...)
	// Keep every non-data line and put the payload on the first data line, so
	// a single-line payload keeps its exact surrounding bytes.
	var out []byte
	written := false
	for line := range bytes.SplitAfterSeq(frame, []byte("\n")) {
		trimmed := bytes.TrimRight(line, "\r\n")
		part, ok := bytes.CutPrefix(trimmed, []byte("data:"))
		if !ok {
			out = append(out, line...)
			continue
		}
		if written {
			continue
		}
		written = true
		out = append(out, "data:"...)
		if bytes.HasPrefix(part, []byte(" ")) {
			out = append(out, ' ')
		}
		out = append(out, shifted...)
		out = append(out, line[len(trimmed):]...)
	}
	return out
}

// blockFrames encodes a complete text block at index 0.
func blockFrames(text, eol string) []byte {
	encoded := string(encodeJSONString(text))
	return []byte("event: content_block_start" + eol +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + eol + eol +
		"event: content_block_delta" + eol +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + encoded + `}}` + eol + eol +
		"event: content_block_stop" + eol +
		`data: {"type":"content_block_stop","index":0}` + eol + eol)
}

func lineEnding(frame []byte) string {
	if bytes.Contains(frame, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

type jsonSpan struct{ start, end int }

// insertFirstBlock adds a text block at the start of a message's content
// array, leaving every other byte of the response unchanged.
func insertFirstBlock(input []byte, text string) ([]byte, bool) {
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
		if token, err := dec.Token(); err != nil || token != json.Delim('[') {
			return nil, false
		}
		at := int(dec.InputOffset())
		block := `{"type":"text","text":` + string(encodeJSONString(text)) + `}`
		if dec.More() {
			block += ","
		}
		out := make([]byte, 0, len(input)+len(block))
		out = append(out, input[:at]...)
		out = append(out, block...)
		return append(out, input[at:]...), true
	}
	return nil, false
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
