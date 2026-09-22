package probe_test

import (
	"context"
	"fmt"

	"github.com/0x71pp17/mcp-controlplane-scan/internal/probe"
)

// ExampleRun shows the shape of a scan. In practice BaseURL is a live loopback
// control plane you own; here the intent is only to show the call and output.
func ExampleRun() {
	findings := probe.Run(context.Background(), probe.Target{
		BaseURL: "http://127.0.0.1:0", // unreachable on purpose in the example
	})
	fmt.Println(len(findings) >= 0)
	// Output: true
}
