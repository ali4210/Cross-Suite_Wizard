package repohealer

import (
	"strings"
	"testing"
)

func readyHashiCorpAPTListRepairPreflightProbeOutput() string {
	return strings.Join([]string{
		"VERSION|1",
		"FILE|source|present|0|644|126|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"FILE|keyring|missing",
		"TOOL|apt-get|1",
		"TOOL|gpg|1",
		"TOOL|install|1",
		"TOOL|mv|1",
		"TOOL|sha256sum|1",
		"LOCK|apt_dpkg|0",
	}, "\n")
}

func TestParseHashiCorpAPTListRepairPreflightProbeOutputAcceptsSafeProbe(
	t *testing.T,
) {
	got, err := parseHashiCorpAPTListRepairPreflightProbeOutput(
		readyHashiCorpAPTListRepairPreflightProbeOutput(),
	)
	if err != nil {
		t.Fatalf("parseHashiCorpAPTListRepairPreflightProbeOutput() error = %v", err)
	}

	if got.Source.State != HashiCorpAPTListRepairPreflightFilePresent {
		t.Fatalf("source state = %q", got.Source.State)
	}
	if got.Source.UID != 0 || got.Source.Mode != "644" ||
		got.Source.Size != 126 {
		t.Fatalf("source metadata = %#v", got.Source)
	}
	if got.Keyring.State != HashiCorpAPTListRepairPreflightFileMissing {
		t.Fatalf("keyring state = %q", got.Keyring.State)
	}
	if !got.APTAvailable || !got.GPGAvailable ||
		!got.InstallAvailable || !got.MVAvailable ||
		!got.SHA256Available {
		t.Fatalf("tool availability = %#v", got)
	}
	if got.APTLockActive {
		t.Fatalf("APT lock unexpectedly active")
	}
}

func TestParseHashiCorpAPTListRepairPreflightProbeOutputRejectsUnsafeOutput(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func([]string) []string
		want   string
	}{
		{
			name: "Missing version",
			mutate: func(lines []string) []string {
				return lines[1:]
			},
			want: "version",
		},
		{
			name: "Unsupported version",
			mutate: func(lines []string) []string {
				lines[0] = "VERSION|2"
				return lines
			},
			want: "version",
		},
		{
			name: "Unknown record",
			mutate: func(lines []string) []string {
				return append(lines, "EXTRA|value")
			},
			want: "unknown",
		},
		{
			name: "Blank record",
			mutate: func(lines []string) []string {
				return append(lines, "")
			},
			want: "blank",
		},
		{
			name: "Duplicate source",
			mutate: func(lines []string) []string {
				return append(lines, lines[1])
			},
			want: "duplicate",
		},
		{
			name: "Missing keyring",
			mutate: func(lines []string) []string {
				return append(lines[:2], lines[3:]...)
			},
			want: "keyring",
		},
		{
			name: "Source missing metadata",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|present"
				return lines
			},
			want: "source",
		},
		{
			name: "Missing keyring has metadata",
			mutate: func(lines []string) []string {
				lines[2] = "FILE|keyring|missing|0|644|1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				return lines
			},
			want: "keyring",
		},
		{
			name: "Invalid source state",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|mystery|0|644|126|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				return lines
			},
			want: "source",
		},
		{
			name: "Invalid tool value",
			mutate: func(lines []string) []string {
				lines[3] = "TOOL|apt-get|yes"
				return lines
			},
			want: "apt-get",
		},
		{
			name: "Missing tool",
			mutate: func(lines []string) []string {
				return append(lines[:4], lines[5:]...)
			},
			want: "gpg",
		},
		{
			name: "Invalid lock value",
			mutate: func(lines []string) []string {
				lines[8] = "LOCK|apt_dpkg|unknown"
				return lines
			},
			want: "lock",
		},
		{
			name: "Duplicate lock",
			mutate: func(lines []string) []string {
				return append(lines, lines[8])
			},
			want: "duplicate",
		},
		{
			name: "Missing source",
			mutate: func(lines []string) []string {
				return append(lines[:1], lines[2:]...)
			},
			want: "source",
		},
		{
			name: "Source marked missing",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|missing"
				return lines
			},
			want: "source",
		},
		{
			name: "Duplicate tool",
			mutate: func(lines []string) []string {
				return append(lines, lines[3])
			},
			want: "duplicate",
		},
		{
			name: "Unknown tool",
			mutate: func(lines []string) []string {
				lines[3] = "TOOL|curl|1"
				return lines
			},
			want: "tool",
		},
		{
			name: "Invalid source UID",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|present|root|644|126|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				return lines
			},
			want: "source",
		},
		{
			name: "Negative source size",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|present|0|644|-1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				return lines
			},
			want: "source",
		},
		{
			name: "Unsafe owner missing metadata",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|unsafe_owner"
				return lines
			},
			want: "source",
		},
		{
			name: "Invalid source mode",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|present|0|64|126|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				return lines
			},
			want: "source",
		},
		{
			name: "Invalid source SHA-256",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|present|0|644|126|not-a-sha256"
				return lines
			},
			want: "source",
		},
		{
			name: "Uppercase source SHA-256",
			mutate: func(lines []string) []string {
				lines[1] = "FILE|source|present|0|644|126|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				return lines
			},
			want: "source",
		},
		{
			name: "Symlink malformed metadata",
			mutate: func(lines []string) []string {
				lines[2] = "FILE|keyring|symlink|root|bad|-1|not-a-sha256"
				return lines
			},
			want: "keyring",
		},
		{
			name: "Symlink without metadata",
			mutate: func(lines []string) []string {
				lines[2] = "FILE|keyring|symlink"
				return lines
			},
			want: "",
		},
		{
			name: "Unreadable without metadata",
			mutate: func(lines []string) []string {
				lines[2] = "FILE|keyring|unreadable"
				return lines
			},
			want: "",
		},
		{
			name: "CRLF output",
			mutate: func(lines []string) []string {
				return []string{strings.Join(lines, "\r\n")}
			},
			want: "line ending",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lines := strings.Split(
				readyHashiCorpAPTListRepairPreflightProbeOutput(),
				"\n",
			)

			got, err := parseHashiCorpAPTListRepairPreflightProbeOutput(
				strings.Join(test.mutate(lines), "\n"),
			)
			if test.want == "" {
				if err != nil {
					t.Fatalf("parse error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("parse unexpectedly succeeded: %#v", got)
			}
			if !strings.Contains(
				strings.ToLower(err.Error()),
				strings.ToLower(test.want),
			) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err,
					test.want,
				)
			}
		})
	}
}
