package banner

import (
	"encoding/json"
	"testing"
)

func TestNoticeFormat(t *testing.T) {
	notice := Notice([]string{"Card ending in 6467 was redacted", "Card `9903`\nredacted"})
	if notice != "> **⚠ Gaitway:** `Card ending in 6467 was redacted`\n\n> **⚠ Gaitway:** `Card '9903' redacted`" {
		t.Fatalf("unexpected notice: %q", notice)
	}
}

func TestStripInjected(t *testing.T) {
	transformer := NewTransformer("Gaitway Active", NewRegistry(10), 1<<20, 8<<20)
	notice := `{"type":"text","text":"> **⚠ Gaitway:** ` + "`Card ending in 6467 was redacted`" + `\n\n> **⚠ Gaitway:** ` + "`Card ending in 9903 was redacted`" + `"}`
	cases := []struct{ name, body, want string }{
		{
			name: "activation and notice before thinking",
			body: `{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"text","text":"> **Gaitway Active**"}, ` + notice + `, {"type":"thinking","thinking":"x","signature":"s"},{"type":"tool_use","id":"t"}]}]}`,
			want: `{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"thinking","thinking":"x","signature":"s"},{"type":"tool_use","id":"t"}]}]}`,
		},
		{
			name: "role after content and an older activation message",
			body: `{"messages":[{"content":[{"text":"> **Old Name Active**","type":"text"},{"text":"ok","type":"text"}],"role":"assistant"}],"stream":true}`,
			want: `{"messages":[{"content":[{"text":"ok","type":"text"}],"role":"assistant"}],"stream":true}`,
		},
		{
			name: "user blocks are never touched",
			body: `{"messages":[{"role":"user","content":[{"type":"text","text":"> **Gaitway Active**"},{"type":"text","text":"ok"}]}]}`,
			want: `{"messages":[{"role":"user","content":[{"type":"text","text":"> **Gaitway Active**"},{"type":"text","text":"ok"}]}]}`,
		},
		{
			name: "a reply that would be left empty is kept",
			body: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Gaitway Active**"}]}]}`,
			want: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Gaitway Active**"}]}]}`,
		},
		{
			name: "only leading blocks are removed",
			body: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"a"},{"type":"text","text":"> **Gaitway Active**"}]}]}`,
			want: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"a"},{"type":"text","text":"> **Gaitway Active**"}]}]}`,
		},
		{
			name: "text the model wrote that only starts like a notice is kept",
			body: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Note:** see below"},{"type":"text","text":"ok"}]}]}`,
			want: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Note:** see below"},{"type":"text","text":"ok"}]}]}`,
		},
		{
			name: "invalid JSON unchanged",
			body: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Gaitway Active**"},`,
			want: `{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Gaitway Active**"},`,
		},
	}
	for _, tc := range cases {
		if got := string(transformer.StripInjected([]byte(tc.body))); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
}

func TestStripUndoesInsertBlock(t *testing.T) {
	transformer := NewTransformer("Gaitway Active", NewRegistry(10), 1<<20, 8<<20)
	reply := `{"role":"assistant","content":[{"type":"thinking","thinking":"x"},{"type":"text","text":"ok"}]}`
	inserted, ok := insertFirstBlock([]byte(reply), Notice([]string{"Card ending in 6467 was redacted"}))
	if !ok {
		t.Fatal("block not inserted")
	}
	if inserted, ok = insertFirstBlock(inserted, transformer.activation); !ok {
		t.Fatal("activation not inserted")
	}
	body := `{"messages":[` + string(inserted) + `]}`
	if got := string(transformer.StripInjected([]byte(body))); got != `{"messages":[`+reply+`]}` {
		t.Fatalf("history not restored: %s", got)
	}
}

func FuzzStripInjected(f *testing.F) {
	transformer := NewTransformer("Gaitway Active", NewRegistry(10), 1<<20, 8<<20)
	f.Add([]byte(`{"messages":[{"role":"assistant","content":[{"type":"text","text":"> **Gaitway Active**"},{"type":"text","text":"ok"}]}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		got := transformer.StripInjected(body)
		if string(got) != string(body) && !json.Valid(got) {
			t.Fatalf("stripping produced invalid JSON: %q", got)
		}
	})
}
