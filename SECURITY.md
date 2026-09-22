# Security policy

This is a research and demonstration project. If you find a security issue in
the code, report it privately through GitHub's "Report a vulnerability" flow on
this repository rather than opening a public issue.

## Authorized use

`cpscan` sends real HTTP requests, including state-changing ones, to the target
you give it. Run it only against a control plane you own or are explicitly
authorized to test. The tool refuses non-loopback targets, but that is a guard
rail, not permission.
