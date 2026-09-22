# Architecture

## Layout

```
mcp-controlplane-scan/
├── README.md
├── LICENSE
├── Makefile
├── go.mod
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   └── architecture.md
├── SECURITY.md
├── cmd/
│   └── cpscan/
│       ├── main.go           CLI entrypoint
│       └── main_test.go      loopback-guard tests + FuzzIsLoopback
└── internal/
    ├── probe/
    │   ├── finding.go        types, orchestration, Report, Summarize, Result
    │   ├── checks.go         the four checks
    │   ├── probe_test.go     contract test
    │   └── example_test.go   runnable godoc example
    └── reference/
        ├── server.go         hardened reference control plane
        └── server_test.go
```

## What each file owns

| Path | Owns |
|---|---|
| `cmd/cpscan/main.go` | CLI entrypoint: loopback-only target guard, human-readable output, exit code. |
| `internal/probe/finding.go` | Types and orchestration: `Severity`, `Finding`, `Target`, `Check`, `Registry`, `Run`. |
| `internal/probe/checks.go` | The four checks, one `Check` per weakness. |
| `internal/probe/probe_test.go` | Contract test: the scanner against the reference and against an open server. |
| `internal/reference/server.go` | Hardened control plane implementing the four defenses. |

## Checks

| id | severity | Observes |
|---|---|---|
| `host-rebind` | high | a foreign Host header is accepted on a read |
| `state-changing-get` | high | a state-changing route answers a GET |
| `unauthenticated-mutation` | high | a state change is accepted with no Origin or token |
| `unauthenticated-secret-read` | high | secret-shaped content is readable without a token |

## The four defenses the reference implements

| Defense | Closes |
|---|---|
| loopback only | access from the network |
| Host check on every request | DNS rebinding |
| Origin check on state changes | cross-site requests |
| per-session token, reads that expose secrets included | requests with no Origin, and secret reads |

## Contract

The scanner and the reference validate each other. `probe_test.go` asserts the
reference trips no high or medium finding, and that an open server trips every
check. A regression on either side fails the test.

## Extension points

| To add | Change |
|---|---|
| A new check | a type implementing `Check` in `checks.go`, added to `Registry` in `finding.go` |
| A new target shape | the path fields on `Target`, defaulted in `finding.go` |

## Prior art

The checks encode the localhost control-plane threat model: a loopback surface is
reachable from any page in the user's browser, so DNS rebinding, cross-site
requests, and unauthenticated reads are the failure classes. The four defenses in
the reference server are the standard mitigations. The implementation is original.

## Boundary

The scanner sends real requests, including a state-changing POST and GET to the
mutate path. Point it only at a control plane you own or are authorized to test.
The CLI refuses any target that is not a loopback address.
