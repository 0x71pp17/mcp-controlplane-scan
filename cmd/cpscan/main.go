// Command cpscan probes a local AI tool's HTTP control plane and prints any
// findings. Point it at a loopback base URL; it does not scan remote hosts.
//
// Use it only against a control plane you own or are explicitly authorized to
// test: the probes send real requests, including state-changing ones.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/0x71pp17/mcp-controlplane-scan/internal/probe"
)

func main() {
	base := flag.String("target", "http://127.0.0.1:7070", "base URL of the loopback control plane")
	mutate := flag.String("mutate-path", "/api/execute", "a state-changing route to test")
	secret := flag.String("secret-path", "/api/config", "a config or secrets route to test")
	format := flag.String("format", "text", "output format: text or json")
	flag.Parse()

	if !isLoopback(*base) {
		fmt.Fprintln(os.Stderr, "target must be an http loopback address; this tool probes local control planes only")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "cpscan sends real requests, including state-changing ones. Test only control planes you own or are authorized to test.")

	findings := probe.Run(context.Background(), probe.Target{
		BaseURL:    *base,
		MutatePath: *mutate,
		SecretPath: *secret,
	})

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(probe.Result{
			Target:    *base,
			ScannedAt: time.Now().UTC(),
			Findings:  findings,
			Summary:   probe.Summarize(findings),
		}); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(2)
		}
	default:
		fmt.Print(probe.Report(findings))
		s := probe.Summarize(findings)
		fmt.Printf("summary: %d high, %d medium, %d low, %d info\n", s.High, s.Medium, s.Low, s.Info)
	}

	if probe.HighCount(findings) > 0 {
		os.Exit(1)
	}
}

// isLoopback accepts only an http URL whose host is a loopback name. It parses
// the URL rather than matching a prefix, so a host like 127.0.0.1.evil.com or
// 127.0.0.1@evil.com is rejected.
func isLoopback(base string) bool {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}
