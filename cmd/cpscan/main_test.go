package main

import (
	"net/url"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"http://127.0.0.1:7070":     true,
		"http://localhost:8080":     true,
		"http://[::1]:9000":         true,
		"http://192.168.1.10":       false,
		"http://example.com":        false,
		"https://127.0.0.1:443":     false, // only http is probed
		"http://127.0.0.1.evil.com": false, // prefix-match bypass, must be rejected
		"http://localhost.evil.com": false,
		"http://127.0.0.1@evil.com": false, // userinfo trick; real host is evil.com
	}
	for in, want := range cases {
		if got := isLoopback(in); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", in, got, want)
		}
	}
}

// FuzzIsLoopback asserts the guard's core invariant: anything it accepts must
// parse to an http URL whose host is a loopback name. This is the property that
// a prefix match violated.
func FuzzIsLoopback(f *testing.F) {
	f.Add("http://127.0.0.1:7070")
	f.Add("http://127.0.0.1.evil.com")
	f.Add("http://evil.com")
	f.Fuzz(func(t *testing.T, s string) {
		if !isLoopback(s) {
			return
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "http" {
			t.Fatalf("accepted a non-http or unparseable target %q", s)
		}
		switch u.Hostname() {
		case "127.0.0.1", "localhost", "::1":
		default:
			t.Fatalf("accepted non-loopback host %q from %q", u.Hostname(), s)
		}
	})
}
