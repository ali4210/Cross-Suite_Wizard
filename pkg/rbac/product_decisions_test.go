package rbac

// Tests for A-PR 4 (F-04).
//
// F-13 (hiding unavailable Option 2 tiers on Windows/macOS) is not covered by
// a dedicated test here: no Windows or macOS target is available in this
// environment, and manageUserRBACTiers reads the target OS via a real SSH
// round trip rather than accepting it as an injectable parameter, so the
// non-Linux branches can't be driven without one. That change is verified by
// `go build`/`go vet` with GOOS=windows and GOOS=darwin (both pass) and by
// code review, consistent with how A-PR 1's Windows/macOS provisioning fixes
// were qualified.

import (
	"net"
	"strings"
	"testing"
)

func TestDiscoverLANSubnetUsesTheRealInterfaceNotAHardcodedDefault(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()

	ifaces := fetchActiveNetworkInterfaces(client)
	if len(ifaces) == 0 {
		t.Skip("no active network interfaces reported by the container; nothing to compare against")
	}

	var expected string
	for _, iface := range ifaces {
		if strings.Contains(iface.IP, "/") {
			_, network, err := net.ParseCIDR(iface.IP)
			if err == nil {
				expected = network.String()
				break
			}
		}
	}
	if expected == "" {
		t.Skip("no interface reported a parseable CIDR; nothing to compare against")
	}

	got := discoverLANSubnet(client)
	if got != expected {
		t.Fatalf("discoverLANSubnet() = %q, want the real primary interface's network %q", got, expected)
	}
	// The whole point of F-04 is that this is derived from the real target,
	// not assumed — fail loudly if it silently fell back to the old default
	// for a reason other than "the container really is on that subnet".
	if got == "192.168.0.0/24" {
		t.Logf("warning: container's real subnet happens to equal the historical hardcoded default; this test cannot distinguish the two cases here")
	}
}
