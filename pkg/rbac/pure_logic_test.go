package rbac

// Fast, container-free unit tests for A-PR 5's quality-gates pass: the small
// pure-logic helpers in rbac.go that earlier PRs didn't already cover
// (validateComplexPassword, containsPort, isNumeric, pad). The F-08 validators
// (isValidUsername, isValidIP, isValidIPOrCIDR, isValidHostname) already have
// their own tests in defense_in_depth_test.go.

import "testing"

func TestValidateComplexPassword(t *testing.T) {
	cases := []struct {
		pass string
		want bool
	}{
		{"Sh0rt!", false},              // too short
		{"alllowercase123!", false},    // no uppercase
		{"ALLUPPERCASE123!", false},    // no lowercase
		{"NoDigitsHere!!!!", false},    // no digit
		{"NoSpecialChars123", false},   // no symbol/punct
		{"ValidPassw0rd!", true},       // meets all four classes, >=12 chars
		{"Exactly12Ch!", true},         // exactly 12 chars (the minimum)
		{"Exactly1Ch!", false},         // 11 chars — one short of the minimum
		{"Tr0ub4dor&3xtra$tuff", true}, // long, mixed, with symbols
	}
	for _, c := range cases {
		if got := validateComplexPassword(c.pass); got != c.want {
			t.Errorf("validateComplexPassword(%q) = %v, want %v", c.pass, got, c.want)
		}
	}
}

func TestContainsPort(t *testing.T) {
	ports := []string{"22", "80", "443"}
	if !containsPort(ports, "80") {
		t.Error("expected containsPort to find an existing entry")
	}
	if containsPort(ports, "8080") {
		t.Error("expected containsPort to report false for a missing entry")
	}
	if containsPort(nil, "80") {
		t.Error("expected containsPort to report false on a nil slice")
	}
}

func TestIsNumeric(t *testing.T) {
	valid := []string{"0", "22", "65535", "-1"}
	for _, v := range valid {
		if !isNumeric(v) {
			t.Errorf("expected %q to be numeric", v)
		}
	}
	invalid := []string{"", "abc", "22;rm -rf /", "22 80", "22.5", "0x16"}
	for _, v := range invalid {
		if isNumeric(v) {
			t.Errorf("expected %q to be rejected as non-numeric", v)
		}
	}
}

func TestPad(t *testing.T) {
	if got := pad("abc", 6); got != "abc   " {
		t.Errorf("pad(%q, 6) = %q, want %q", "abc", got, "abc   ")
	}
	if got := pad("abcdefgh", 4); got != "abcd" {
		t.Errorf("pad(%q, 4) = %q, want %q", "abcdefgh", got, "abcd")
	}
	if got := pad("abcd", 4); got != "abcd" {
		t.Errorf("pad(%q, 4) = %q, want %q", "abcd", got, "abcd")
	}
}
