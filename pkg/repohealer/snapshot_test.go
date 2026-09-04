package repohealer

import (
	"testing"
)

func TestShellArrayContainsTargets(t *testing.T) {
	got := shellArray([]string{
		"/etc/apt/sources.list.d/vscode.list",
		"/etc/apt/keyrings/microsoft.gpg",
	})

	for _, expected := range []string{
		"/etc/apt/sources.list.d/vscode.list",
		"/etc/apt/keyrings/microsoft.gpg",
	} {
		if !contains(got, expected) {
			t.Fatalf("shell array does not contain %q: %s", expected, got)
		}
	}
}

func contains(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		if value[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
