// Package reference is a control plane that passes every probe in
// ../probe. It is the worked example of the four defenses a loopback HTTP
// surface needs, and the scanner's contract test runs against it to prove the
// scanner and the reference agree.
package reference

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
)

// NewToken returns a fresh 32-byte session token as hex. Regenerate it at every
// start and never write it to disk.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("cannot generate session token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Server is a hardened loopback control plane.
type Server struct {
	token string
}

func New(token string) *Server { return &Server{token: token} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/api/execute", s.guard(true, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"done"}`))
	}))
	mux.HandleFunc("/api/config", s.restrictedRead(func(w http.ResponseWriter, r *http.Request) {
		// The token has already cleared. A real server returns keys masked.
		_ = json.NewEncoder(w).Encode(map[string]string{"provider": "example", "api_key": "****last4"})
	}))
	return mux
}

// guard applies the four independent defenses. mutating routes additionally
// require a matching Origin and the session token, and answer POST only.
func (s *Server) guard(mutating bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localAddr(r.RemoteAddr) {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		if !allowedHost(r.Host) {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		if mutating {
			if r.Method != http.MethodPost {
				http.Error(w, "post only", http.StatusMethodNotAllowed)
				return
			}
			if !allowedOrigin(r.Header.Get("Origin")) {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
			if !s.tokenOK(r) {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// restrictedRead is a GET that returns sensitive config, so it demands the token
// even though it does not mutate, plus the host check every route gets.
func (s *Server) restrictedRead(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localAddr(r.RemoteAddr) || !allowedHost(r.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !s.tokenOK(r) {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-CP-Token")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func localAddr(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func allowedHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // Host may arrive without a port
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func allowedOrigin(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}
