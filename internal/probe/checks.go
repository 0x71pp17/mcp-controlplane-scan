package probe

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// HostRebindCheck sends a benign read with a foreign Host header. A control
// plane that answers is reachable by DNS rebinding: an attacker page whose
// domain resolves to the loopback address becomes same-origin and can read the
// tool's responses. The Host check must fire on reads, not only on writes.
type HostRebindCheck struct{}

func (HostRebindCheck) ID() string { return "host-rebind" }

func (c HostRebindCheck) Run(ctx context.Context, t Target) []Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.BaseURL+t.read(), nil)
	if err != nil {
		return nil
	}
	req.Host = "panel.attacker.example"
	resp, err := t.client().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		return []Finding{{
			Check:       c.ID(),
			Severity:    SevHigh,
			Title:       "Foreign Host header accepted on a read",
			Evidence:    "GET " + t.read() + " with Host: panel.attacker.example returned " + resp.Status,
			Remediation: "Reject any request whose Host is not the loopback authority the server binds, on reads as well as writes.",
		}}
	}
	return nil
}

// StateChangingGETCheck asks whether a state-changing route answers a GET. If it
// does, an <img src> or a top-level navigation from any page triggers it with no
// script and no token.
type StateChangingGETCheck struct{}

func (StateChangingGETCheck) ID() string { return "state-changing-get" }

func (c StateChangingGETCheck) Run(ctx context.Context, t Target) []Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.BaseURL+t.mutate(), nil)
	if err != nil {
		return nil
	}
	resp, err := t.client().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return nil
	}
	if resp.StatusCode < 300 {
		return []Finding{{
			Check:       c.ID(),
			Severity:    SevHigh,
			Title:       "State-changing route answers GET",
			Evidence:    "GET " + t.mutate() + " returned " + resp.Status + " instead of 405",
			Remediation: "Serve state-changing routes on POST only, so a cross-site GET cannot invoke them.",
		}}
	}
	return nil
}

// UnauthedMutationCheck posts to a state-changing route with no Origin and no
// token. A control plane that acts on it can be driven cross-site.
type UnauthedMutationCheck struct{}

func (UnauthedMutationCheck) ID() string { return "unauthenticated-mutation" }

func (c UnauthedMutationCheck) Run(ctx context.Context, t Target) []Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.BaseURL+t.mutate(), strings.NewReader("{}"))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		return []Finding{{
			Check:       c.ID(),
			Severity:    SevHigh,
			Title:       "State change accepted without Origin or token",
			Evidence:    "POST " + t.mutate() + " with no Origin and no token returned " + resp.Status,
			Remediation: "Require a matching Origin and a per-session token, regenerated each start, on every state-changing request.",
		}}
	}
	return nil
}

var secretPattern = regexp.MustCompile(`(?i)"?(api[_-]?key|secret|password|bearer|authorization)"?\s*[:=]|sk-[A-Za-z0-9]{8,}`)

// UnauthedSecretReadCheck reads a config or secrets route with no token and
// looks for secret-shaped content in the body. It is a heuristic: a hit is a
// finding, a clean 200 is reported as info so a caller can confirm by hand.
type UnauthedSecretReadCheck struct{}

func (UnauthedSecretReadCheck) ID() string { return "unauthenticated-secret-read" }

func (c UnauthedSecretReadCheck) Run(ctx context.Context, t Target) []Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.BaseURL+t.secret(), nil)
	if err != nil {
		return nil
	}
	resp, err := t.client().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if secretPattern.Match(body) {
		return []Finding{{
			Check:       c.ID(),
			Severity:    SevHigh,
			Title:       "Secret-shaped content readable without a token",
			Evidence:    "GET " + t.secret() + " returned " + resp.Status + " with credential-shaped fields in the body",
			Remediation: "Require the session token on config and secret reads, and return only a masked form of any provider key.",
		}}
	}
	return []Finding{{
		Check:       c.ID(),
		Severity:    SevInfo,
		Title:       "Config route readable without a token",
		Evidence:    "GET " + t.secret() + " returned " + resp.Status + " with no secret-shaped fields matched",
		Remediation: "Confirm by hand that this route exposes no sensitive values before treating it as clear.",
	}}
}
