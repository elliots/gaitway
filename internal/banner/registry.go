package banner

import "sync"

type state uint8

const (
	claimed state = iota + 1
	emitted
)

// Registry remembers which Claude sessions have received the activation
// message during this process epoch.
type Registry struct {
	mu       sync.Mutex
	max      int
	sessions map[string]state
}

func NewRegistry(max int) *Registry {
	return &Registry{max: max, sessions: make(map[string]state)}
}

func (r *Registry) Claim(session string) bool {
	if session == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[session]; exists {
		return false
	}
	if r.max <= 0 || len(r.sessions) >= r.max {
		return false
	}
	r.sessions[session] = claimed
	return true
}

func (r *Registry) Release(session string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[session] == claimed {
		delete(r.sessions, session)
	}
}

func (r *Registry) MarkEmitted(session string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[session] == claimed {
		r.sessions[session] = emitted
	}
}
