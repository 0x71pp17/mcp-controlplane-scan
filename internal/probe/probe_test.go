package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x71pp17/mcp-controlplane-scan/internal/reference"
)

// The reference control plane must pass its own scanner. If a check fires
// against it, either the reference regressed or the check is wrong; either way
// it is caught here.
func TestReferenceServerHasNoHighOrMediumFindings(t *testing.T) {
	srv := httptest.NewServer(reference.New("test-token").Handler())
	defer srv.Close()

	findings := Run(context.Background(), Target{BaseURL: srv.URL, Client: srv.Client()})
	for _, f := range findings {
		if f.Severity == SevHigh || f.Severity == SevMedium {
			t.Errorf("reference server tripped %s (%s): %s", f.Check, f.Severity, f.Evidence)
		}
	}
}

// A deliberately open control plane must trip every check, so the scanner is
// shown to detect and not merely to stay quiet.
func TestOpenServerTripsEveryCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/api/execute", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"api_key": "sk-abcdef012345"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	findings := Run(context.Background(), Target{BaseURL: srv.URL, Client: srv.Client()})
	want := map[string]bool{
		"host-rebind":                 false,
		"state-changing-get":          false,
		"unauthenticated-mutation":    false,
		"unauthenticated-secret-read": false,
	}
	for _, f := range findings {
		if f.Severity == SevHigh {
			want[f.Check] = true
		}
	}
	for id, tripped := range want {
		if !tripped {
			t.Errorf("check %q did not fire against an open control plane", id)
		}
	}
}

func TestReportRendersAndEmptyCase(t *testing.T) {
	if got := Report(nil); got != "no findings\n" {
		t.Errorf("empty report = %q", got)
	}
	out := Report([]Finding{{Check: "x", Severity: SevHigh, Title: "T", Evidence: "E", Remediation: "F"}})
	for _, want := range []string{"HIGH", "T", "E", "fix: F"} {
		if !contains(out, want) {
			t.Errorf("report missing %q in %q", want, out)
		}
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestSummarize(t *testing.T) {
	s := Summarize([]Finding{
		{Severity: SevHigh}, {Severity: SevHigh}, {Severity: SevInfo}, {Severity: SevLow},
	})
	if s.High != 2 || s.Low != 1 || s.Info != 1 || s.Medium != 0 {
		t.Errorf("summary = %+v", s)
	}
}
