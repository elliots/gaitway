package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gaitway/internal/archive"
	"gaitway/internal/audit"
)

type Server struct {
	events   audit.Store
	objects  archive.Store
	template *template.Template
}

func New(events audit.Store, objects archive.Store) (*Server, error) {
	page, err := template.New("dashboard").Funcs(template.FuncMap{
		"short": func(value string) string {
			if len(value) <= 12 {
				return value
			}
			return value[:12] + "…"
		},
	}).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	return &Server{events: events, objects: objects, template: page}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/events", s.listEvents)
	mux.HandleFunc("GET /api/content/{ref}", s.rawContent)
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	return securityHeaders(mux)
}

func (s *Server) index(writer http.ResponseWriter, request *http.Request) {
	events, err := s.filteredEvents(request)
	if err != nil {
		http.Error(writer, "audit data unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	principals := make(map[string]struct{})
	sessions := make(map[string]struct{})
	var inputTokens, outputTokens int64
	for _, event := range events {
		if event.Principal != "" {
			principals[event.Principal] = struct{}{}
		}
		if event.Session != "" {
			sessions[event.Session] = struct{}{}
		}
		inputTokens += event.InputTokens
		outputTokens += event.OutputTokens
	}
	_ = s.template.Execute(writer, struct {
		Events                    []audit.Event
		Query                     string
		Principals, Sessions      int
		InputTokens, OutputTokens int64
	}{Events: events, Query: request.URL.Query().Get("q"), Principals: len(principals), Sessions: len(sessions), InputTokens: inputTokens, OutputTokens: outputTokens})
}

func (s *Server) listEvents(writer http.ResponseWriter, request *http.Request) {
	events, err := s.filteredEvents(request)
	if err != nil {
		http.Error(writer, "audit data unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"events": events, "count": len(events)})
}

func (s *Server) filteredEvents(request *http.Request) ([]audit.Event, error) {
	limit := 100
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			return nil, fmt.Errorf("invalid limit")
		}
		limit = parsed
	}
	events, err := s.events.List(request.Context(), 1000)
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("q")))
	typeFilter := request.URL.Query().Get("type")
	filtered := make([]audit.Event, 0, limit)
	for _, event := range events {
		if typeFilter != "" && event.Type != typeFilter {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(event.Principal+" "+event.Session+" "+event.Username+" "+event.Hostname+" "+event.Route+" "+event.Model+" "+event.Outcome+" "+event.Policy+" "+event.Rule+" "+event.ToolName+" "+event.Classification), query) {
			continue
		}
		filtered = append(filtered, event)
		if len(filtered) == limit {
			break
		}
	}
	return filtered, nil
}

func (s *Server) rawContent(writer http.ResponseWriter, request *http.Request) {
	ref := request.PathValue("ref")
	body, err := s.objects.Read(request.Context(), ref)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	if err := s.events.Append(context.WithoutCancel(request.Context()), audit.Event{
		ID: randomAccessID(), RequestID: randomAccessID(), Type: "raw_access", Time: time.Now().UTC(), Outcome: "viewed", ContentRef: ref,
	}); err != nil {
		http.Error(writer, "raw access could not be audited", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", "inline")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = writer.Write(body)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func randomAccessID() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Gaitway</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    body { margin: 0; background: #0b1020; color: #e6edf7; }
    header, main { max-width: 1180px; margin: auto; padding: 24px; }
    header { display: flex; justify-content: space-between; align-items: baseline; }
    h1 { color: #7ee787; margin: 0; }
    .warning { background: #4c2d00; color: #ffd8a8; padding: 12px; border: 1px solid #9a6700; border-radius: 6px; }
    form { display: flex; gap: 8px; margin: 20px 0; }
	.stats { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; margin: 20px 0; }
	.stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }
	.stat strong { display: block; color: #7ee787; font-size: 20px; }
    input, button { font: inherit; padding: 9px; border-radius: 5px; border: 1px solid #30363d; }
    input { flex: 1; background: #161b22; color: inherit; }
    button { background: #238636; color: white; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; background: #0d1117; font-size: 13px; }
    th, td { padding: 9px; border-bottom: 1px solid #21262d; text-align: left; vertical-align: top; }
    th { color: #8c959f; position: sticky; top: 0; background: #161b22; }
    a { color: #58a6ff; }
    .pill { border: 1px solid #30363d; border-radius: 99px; padding: 2px 7px; white-space: nowrap; }
  </style>
</head>
<body>
<header><h1>*** Gaitway Active ***</h1><span>read-only pilot console</span></header>
<main>
  <p class="warning"><strong>No application authentication.</strong> Bind this console only to a trusted private interface.</p>
	<div class="stats"><div class="stat"><strong>{{.Principals}}</strong>principals</div><div class="stat"><strong>{{.Sessions}}</strong>sessions</div><div class="stat"><strong>{{.InputTokens}}</strong>input tokens</div><div class="stat"><strong>{{.OutputTokens}}</strong>output tokens</div></div>
  <form method="get"><input name="q" value="{{.Query}}" placeholder="filter principal, session, route, model, outcome"><button>Filter</button></form>
  <table><thead><tr><th>Time</th><th>Type</th><th>Principal / Session</th><th>Route / Model</th><th>Outcome</th><th>Tokens</th><th>Evidence</th></tr></thead>
  <tbody>{{range .Events}}<tr>
    <td>{{.Time.Format "2006-01-02 15:04:05Z07:00"}}</td><td><span class="pill">{{.Type}}</span></td>
    <td>{{if .Username}}{{.Username}} @ {{.Hostname}}<br>{{end}}{{short .Principal}}<br>{{short .Session}}</td><td>{{.Route}}<br>{{.Model}}{{if .ToolName}}<br>{{.ToolName}}{{end}}</td>
	<td>{{.Outcome}}{{if .Policy}}<br>{{.Policy}}/{{.Rule}}{{end}}{{if .Classification}}<br>{{.Classification}}{{end}}</td><td>{{.InputTokens}} in<br>{{.OutputTokens}} out</td>
    <td>{{if .ContentRef}}<a href="/api/content/{{.ContentRef}}">open raw</a><br>{{.ContentSize}} bytes{{end}}</td>
  </tr>{{else}}<tr><td colspan="7">No events yet.</td></tr>{{end}}</tbody></table>
</main></body></html>`
