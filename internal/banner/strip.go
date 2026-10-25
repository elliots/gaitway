package banner

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

var errUnexpectedJSON = errors.New("unexpected JSON shape")

// noticePrefix renders as a bold quote in Claude Code's markdown output; the
// notice itself is inline code, which Claude Code shows in its accent colour.
const noticePrefix = "> **⚠ Gaitway:** `"

// Activation formats the once-per-session activation message as a bold quote.
func Activation(message string) string { return "> **" + message + "**" }

// Notice formats policy notices as one block: a quoted paragraph per notice.
// StripInjected recognises exactly this shape.
func Notice(texts []string) string {
	paragraphs := make([]string, 0, len(texts))
	for _, text := range texts {
		text = strings.NewReplacer("\n", " ", "`", "'").Replace(text)
		paragraphs = append(paragraphs, noticePrefix+text+"`")
	}
	return strings.Join(paragraphs, "\n\n")
}

// StripInjected removes the text blocks Gaitway inserted at the start of
// earlier assistant replies, so history sent upstream matches what the model
// wrote. This also keeps a reply's thinking block first, which the API
// requires when thinking and tool use are combined. Unparseable bodies are
// returned unchanged.
func (t *Transformer) StripInjected(body []byte) []byte {
	if !bytes.Contains(body, []byte("> **")) || !json.Valid(body) {
		return body
	}
	var removals []jsonSpan
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return body
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return body
		}
		if key != "messages" {
			if skipJSONValue(dec) != nil {
				return body
			}
			continue
		}
		if token, err := dec.Token(); err != nil || token != json.Delim('[') {
			return body
		}
		for dec.More() {
			span, err := t.injectedBlocks(dec, body)
			if err != nil {
				return body
			}
			if span.end > span.start {
				removals = append(removals, span)
			}
		}
		break
	}
	if len(removals) == 0 {
		return body
	}
	out := make([]byte, 0, len(body))
	last := 0
	for _, span := range removals {
		out = append(out, body[last:span.start]...)
		last = span.end
	}
	return append(out, body[last:]...)
}

// isInjected reports whether a whole text block is Gaitway's: the configured
// activation, any activation-shaped line left by an earlier configuration, or
// a notice block.
func (t *Transformer) isInjected(text string) bool {
	if t != nil && t.activation != "" && text == t.activation {
		return true
	}
	if strings.HasPrefix(text, "> **") && strings.HasSuffix(text, "**") && len(text) > len("> ****") && !strings.Contains(text, "\n") {
		return true
	}
	for paragraph := range strings.SplitSeq(text, "\n\n") {
		if !strings.HasPrefix(paragraph, noticePrefix) || !strings.HasSuffix(paragraph, "`") || strings.Contains(paragraph, "\n") {
			return false
		}
	}
	return true
}

// injectedBlocks reads one message and returns the span covering its leading
// Gaitway blocks, from the first block up to the next real one. It returns an
// empty span for user messages, string content, and replies that would be
// left with no content.
func (t *Transformer) injectedBlocks(dec *json.Decoder, input []byte) (jsonSpan, error) {
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return jsonSpan{}, errUnexpectedJSON
	}
	var role string
	var span jsonSpan
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return jsonSpan{}, err
		}
		switch key {
		case "role":
			value, err := dec.Token()
			if err != nil {
				return jsonSpan{}, err
			}
			role, _ = value.(string)
		case "content":
			value, err := dec.Token()
			if err != nil {
				return jsonSpan{}, err
			}
			if value != json.Delim('[') {
				if delim, ok := value.(json.Delim); ok {
					if err := skipJSONContainer(dec, delim); err != nil {
						return jsonSpan{}, err
					}
				}
				continue
			}
			leading, injectedFrom := true, -1
			for dec.More() {
				start := int(dec.InputOffset())
				start += bytes.IndexByte(input[start:], '{')
				text, isText, err := contentBlock(dec)
				if err != nil {
					return jsonSpan{}, err
				}
				switch {
				case !leading:
				case isText && t.isInjected(text):
					if injectedFrom < 0 {
						injectedFrom = start
					}
				default:
					leading = false
					if injectedFrom >= 0 {
						span = jsonSpan{start: injectedFrom, end: start}
					}
				}
			}
			if _, err := dec.Token(); err != nil {
				return jsonSpan{}, err
			}
		default:
			if err := skipJSONValue(dec); err != nil {
				return jsonSpan{}, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return jsonSpan{}, err
	}
	if role != "assistant" {
		return jsonSpan{}, nil
	}
	return span, nil
}

// contentBlock reads one content block and returns its text when it is a
// text block.
func contentBlock(dec *json.Decoder) (string, bool, error) {
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return "", false, errUnexpectedJSON
	}
	var typ, text string
	hasText := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		value, err := dec.Token()
		if err != nil {
			return "", false, err
		}
		switch key {
		case "type":
			typ, _ = value.(string)
		case "text":
			text, hasText = value.(string)
		}
		if delim, ok := value.(json.Delim); ok && (delim == '{' || delim == '[') {
			if err := skipJSONContainer(dec, delim); err != nil {
				return "", false, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", false, err
	}
	return text, typ == "text" && hasText, nil
}

func encodeJSONString(value string) []byte {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
}
