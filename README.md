# mcp-controlplane-scan

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
![CI](https://github.com/0x71pp17/mcp-controlplane-scan/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

> Authorized use only. `cpscan` sends real requests, including state-changing
> ones. Run it only against a control plane you own or are authorized to test.
> The tool refuses non-loopback targets, but that is a guard rail, not permission.

A scanner for the HTTP control plane that local AI tools and MCP servers expose
on the loopback interface, and a hardened reference server that passes it.

## Why a loopback control plane needs defending

A tool that binds `127.0.0.1` and serves a browser UI is reachable from any page
the user has open. The source address stays `127.0.0.1` because it is the user's
own browser making the request, so checking the source is not enough. Four
controls close the gaps, and they are independent:

1. Loopback only, so the network cannot reach it.
2. A Host check on every request, reads included, which closes DNS rebinding.
3. An Origin check on state changes, which closes cross-site requests.
4. A per-session token, regenerated each start and never persisted, which covers
   requests where the browser sends no Origin, and which is also required on any
   read that returns secrets.

## Checks

| id | severity | what it observes |
|---|---|---|
| `host-rebind` | high | a foreign Host header is accepted on a read |
| `state-changing-get` | high | a state-changing route answers a GET |
| `unauthenticated-mutation` | high | a state change is accepted with no Origin or token |
| `unauthenticated-secret-read` | high | secret-shaped content is readable without a token |

## Run

```bash
go run ./cmd/cpscan -target http://127.0.0.1:7070 \
  -mutate-path /api/execute -secret-path /api/config

# machine-readable output for a pipeline
go run ./cmd/cpscan -target http://127.0.0.1:7070 -format json
```

Exit code is 1 when any high-severity finding is present, 2 on a usage error.

The scanner refuses any target that is not a loopback address. It probes local
control planes and does not scan remote hosts.

## Example output

Against an unhardened control plane, JSON mode emits a self-describing envelope:

```json
{
  "target": "http://127.0.0.1:7070",
  "scanned_at": "2026-09-22T00:00:00Z",
  "findings": [
    {
      "check": "host-rebind",
      "severity": "high",
      "title": "Foreign Host header accepted on a read",
      "evidence": "GET / with Host: panel.attacker.example returned 200 OK",
      "remediation": "Reject any request whose Host is not the loopback authority the server binds, on reads as well as writes."
    }
  ],
  "summary": { "high": 4, "medium": 0, "low": 0, "info": 0 }
}
```

Text mode prints each finding followed by a one-line severity summary. The exit
code is 1 when any high-severity finding is present, 2 on a usage error.

## Scope and boundaries

In scope: detection of four control-plane failure classes (foreign Host on a
read, state-changing GET, unauthenticated mutation, unauthenticated secret read)
against an http loopback target, plus a hardened reference server that passes
them.

Out of scope, by design:

- Remote hosts. The tool probes loopback control planes only and refuses any other target.
- Deep or authenticated scanning. It sends one request per check, not a crawl.
- Non-HTTP control planes and application business-logic issues.
- Certainty on the secret-read check, which is a heuristic: a match is a finding, a clean read is reported as info for manual confirmation.

Authorized use only: the probes send real requests, including state-changing
ones. Run it only against a control plane you own or are authorized to test.

## Prior art

The checks encode the localhost control-plane threat model: a loopback HTTP
surface is reachable from any page in the user's browser, so source-address
checks are insufficient and DNS rebinding, cross-site requests, and
unauthenticated reads are the failure classes. The four defenses in the
reference server are the standard mitigations for that model.

## Reference server

`internal/reference` implements the four controls. The contract test in
`internal/probe/probe_test.go` runs the scanner against it and asserts no high
or medium findings, and runs the scanner against an open server and asserts
every check fires, so the scanner and the reference validate each other.

```bash
go test ./...
```
