package playbook

import "testing"

func TestValidateDeepUninstallToolName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
		want    string
	}{
		{"simple name", "docker", false, "docker"},
		{"mixed case normalized", "Docker", false, "docker"},
		{"strips extension", "docker.exe", false, "docker"},
		{"empty", "", true, ""},
		{"whitespace only", "   ", true, ""},
		{"too short", "a", true, ""},
		{"path separator", "foo/bar", true, ""},
		{"backslash", "foo\\bar", true, ""},
		{"path traversal", "../etc", true, ""},
		{"double quote injection", `foo"; rm -rf / #`, true, ""},
		{"single quote injection", "foo'; rm -rf / #", true, ""},
		{"backtick injection", "foo`rm -rf /`", true, ""},
		{"dollar injection", "foo$(rm -rf /)", true, ""},
		{"semicolon", "foo;bar", true, ""},
		{"system critical etc", "etc", true, ""},
		{"system critical root", "root", true, ""},
		{"system critical windows", "windows", true, ""},
		{"leading digit rejected", "1docker", true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateDeepUninstallToolName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateDeepUninstallToolName(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDeepUninstallToolName(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("validateDeepUninstallToolName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateCustomRepoURL(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid https", "https://example.com/repo/", false},
		{"valid http", "http://example.com/repo/", false},
		{"valid ftp", "ftp://example.com/repo/", false},
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"missing host", "https:///repo", true},
		{"unsupported scheme", "file:///etc/passwd", true},
		{"backtick injection", "https://example.com/`rm -rf /`", true},
		{"dollar injection", "https://example.com/$(rm -rf /)", true},
		{"double quote injection", `https://example.com/"; rm -rf / #`, true},
		{"single quote injection", "https://example.com/'; rm -rf / #", true},
		{"semicolon injection", "https://example.com/;rm -rf /", true},
		{"pipe injection", "https://example.com/|rm -rf /", true},
		{"not a url", "not a url at all", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCustomRepoURL(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("validateCustomRepoURL(%q) = nil error, want error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateCustomRepoURL(%q) unexpected error: %v", tc.input, err)
			}
		})
	}
}
