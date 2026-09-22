// Package probe checks a local AI tool's HTTP control plane for the failures
// common to agent runtimes and MCP servers that bind a port on the loopback
// interface: a missing Host check (DNS rebinding), unauthenticated state
// changes, state-changing GETs reachable from any page, and secrets readable
// without a token.
package probe

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Severity string

const (
	SevHigh   Severity = "high"
	SevMedium Severity = "medium"
	SevLow    Severity = "low"
	SevInfo   Severity = "info"
)

// Finding is one control-plane weakness observed against a target.
type Finding struct {
	Check       string   `json:"check"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
}

// Target describes the control plane under test. The three paths let a caller
// point the probes at a specific tool without the probes guessing routes.
type Target struct {
	BaseURL    string       // e.g. http://127.0.0.1:7070
	Client     *http.Client // caller-supplied, so timeouts and redirects are controlled
	ReadPath   string       // a benign read endpoint (default "/")
	MutatePath string       // a state-changing endpoint (default "/api/execute")
	SecretPath string       // an endpoint that may return config or secrets (default "/api/config")
}

func (t Target) read() string   { return orDefault(t.ReadPath, "/") }
func (t Target) mutate() string { return orDefault(t.MutatePath, "/api/execute") }
func (t Target) secret() string { return orDefault(t.SecretPath, "/api/config") }

func (t Target) client() *http.Client {
	if t.Client != nil {
		return t.Client
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		// A control-plane probe must not be bounced to another host: observe
		// the first response and stop.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// Check is one control-plane probe. Run never mutates real state beyond the
// request it must send to observe the weakness, and returns nil when the
// control holds.
type Check interface {
	ID() string
	Run(ctx context.Context, t Target) []Finding
}

// Registry is the default set of checks, ordered high-impact first.
func Registry() []Check {
	return []Check{
		HostRebindCheck{},
		StateChangingGETCheck{},
		UnauthedMutationCheck{},
		UnauthedSecretReadCheck{},
	}
}

// Run executes every check in the registry against one target.
func Run(ctx context.Context, t Target) []Finding {
	var out []Finding
	for _, c := range Registry() {
		out = append(out, c.Run(ctx, t)...)
	}
	return out
}

// Report renders findings as human-readable text. An empty slice yields a single
// "no findings" line.
func Report(findings []Finding) string {
	if len(findings) == 0 {
		return "no findings\n"
	}
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "[%s] %s\n    %s\n    fix: %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.Evidence, f.Remediation)
	}
	return b.String()
}

// HighCount returns how many findings are high severity, for an exit code.
func HighCount(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.Severity == SevHigh {
			n++
		}
	}
	return n
}

// Summary counts findings by severity.
type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Summarize tallies a slice of findings by severity.
func Summarize(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SevHigh:
			s.High++
		case SevMedium:
			s.Medium++
		case SevLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

// Result is the self-describing envelope emitted in JSON mode: the target, when
// it was scanned, the findings, and their severity tally.
type Result struct {
	Target    string    `json:"target"`
	ScannedAt time.Time `json:"scanned_at"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}
