package rbac

// Tests for A-PR 3 (F-08, F-09).
//
// F-08's validators are pure functions, so they're covered by fast unit tests
// with no container needed. F-09 (opt-in geo-IP lookup) is tested against the
// real shared container: with the default geoLookupEnabled=false, a user whose
// assigned IP looks public must resolve to the static placeholder, never a
// real geo string — proving no network call is attempted by default. The
// "enabled" path is not independently re-verified against a live ip-api.com
// response here, since this sandbox's container network egress isn't
// guaranteed; the security-relevant property (off by default, no call made)
// is what's tested for real.

import (
	"bufio"
	"strings"
	"testing"
)

func newTestReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

// --- F-08: strict allowlist validators ---

func TestIsValidUsername(t *testing.T) {
	valid := []string{"alice", "_svc", "bob-the-builder", "a", "A1_2-3", strings.Repeat("x", 32)}
	for _, v := range valid {
		if !isValidUsername(v) {
			t.Errorf("expected %q to be a valid username", v)
		}
	}

	invalid := []string{
		"", "o'brien", `o"brien`, "alice;rm -rf /", "alice`whoami`", "alice$(whoami)",
		"alice\nrm -rf /", "alice rm", "1alice", "-alice", strings.Repeat("x", 33),
		"alice|cat", "alice&&reboot", "alice$HOME",
	}
	for _, v := range invalid {
		if isValidUsername(v) {
			t.Errorf("expected %q to be rejected as a username", v)
		}
	}
}

func TestIsValidIP(t *testing.T) {
	valid := []string{"192.168.1.1", "8.8.8.8", "::1", "2001:db8::1", "0.0.0.0"}
	for _, v := range valid {
		if !isValidIP(v) {
			t.Errorf("expected %q to be a valid IP", v)
		}
	}

	invalid := []string{"", "192.168.1.1/24", "1.1.1.1; rm -rf /", "not-an-ip", "1.1.1.1`id`", "1.1.1.1 extra"}
	for _, v := range invalid {
		if isValidIP(v) {
			t.Errorf("expected %q to be rejected as a plain IP", v)
		}
	}
}

func TestIsValidIPOrCIDR(t *testing.T) {
	valid := []string{"192.168.1.1", "192.168.1.0/24", "10.0.0.5/8", "::1", "2001:db8::/32"}
	for _, v := range valid {
		if !isValidIPOrCIDR(v) {
			t.Errorf("expected %q to be a valid IP or CIDR", v)
		}
	}

	invalid := []string{"", "192.168.1.1/24; rm -rf /", "not-an-ip", "192.168.1.1/999", "192.168.1.1`id`"}
	for _, v := range invalid {
		if isValidIPOrCIDR(v) {
			t.Errorf("expected %q to be rejected as an IP/CIDR", v)
		}
	}
}

func TestIsValidHostname(t *testing.T) {
	valid := []string{"host1", "my-server", "a.b.c.example.com", "x", strings.Repeat("a", 63) + ".example.com"}
	for _, v := range valid {
		if !isValidHostname(v) {
			t.Errorf("expected %q to be a valid hostname", v)
		}
	}

	invalid := []string{
		"", "-badstart", "bad-.com", "host;rm -rf /", "host`id`", "host$(id)",
		"host name", "host\nrm -rf /", strings.Repeat("a", 64) + ".example.com",
	}
	for _, v := range invalid {
		if isValidHostname(v) {
			t.Errorf("expected %q to be rejected as a hostname", v)
		}
	}
}

// --- F-09: geo-IP lookup is opt-in, off by default ---

func TestFetchSystemUsersDoesNotContactIPAPIWhenGeoLookupDisabled(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()
	withSavedSudoPassword(t, client, testerPassword)

	prevEnabled := geoLookupEnabled
	geoLookupEnabled = false
	t.Cleanup(func() { geoLookupEnabled = prevEnabled })

	username := "geotestuser"
	c.exec(t, "id -u "+username+" >/dev/null 2>&1 || useradd -m -s /bin/bash "+username)
	// 8.8.8.8 is a real, well-known public IP with a known non-empty geo
	// response from ip-api.com. If resolve_geo ever actually queried it, the
	// result would NOT be the literal placeholder string.
	c.exec(t, "echo '"+username+":8.8.8.8' >> /etc/cross_assigned_ips.txt")
	t.Cleanup(func() {
		c.exec(t, "sed -i '/^"+username+":/d' /etc/cross_assigned_ips.txt || true")
	})

	users := fetchSystemUsers(client)
	var found bool
	for _, u := range users {
		if u.Username == username {
			found = true
			if u.GeoLocation != "Lookup disabled" {
				t.Fatalf("expected GeoLocation to be the disabled placeholder with geoLookupEnabled=false, got %q (this would mean a real network call reached ip-api.com)", u.GeoLocation)
			}
		}
	}
	if !found {
		t.Fatalf("test user %q was not present in fetchSystemUsers output", username)
	}
}

func TestToggleGeoLookupRequiresTypedConfirmationToEnable(t *testing.T) {
	prevEnabled := geoLookupEnabled
	geoLookupEnabled = false
	t.Cleanup(func() { geoLookupEnabled = prevEnabled })

	toggleGeoLookup(newTestReader("\n")) // cancel
	if geoLookupEnabled {
		t.Fatal("expected geo lookup to remain disabled when the operator doesn't type ENABLE")
	}

	toggleGeoLookup(newTestReader("ENABLE\n"))
	if !geoLookupEnabled {
		t.Fatal("expected geo lookup to be enabled after typing ENABLE")
	}

	// Toggling again with it already on must turn it back off unconditionally
	// (no confirmation needed to go back to the safe default).
	toggleGeoLookup(newTestReader("\n"))
	if geoLookupEnabled {
		t.Fatal("expected a second toggle to disable geo lookup again")
	}
}
