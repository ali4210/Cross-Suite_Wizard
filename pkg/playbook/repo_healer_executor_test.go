package playbook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoHealerExecutorUsesSudoBeforeScriptDecode(t *testing.T) {
	sourcePath := filepath.Join("universal_healer.go")

	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}

	text := string(source)

	if strings.Contains(text, "base64 -d | sudo -n") {
		t.Fatal("repo-healer executor must not decode a script before sudo succeeds")
	}

	if !strings.Contains(
		text,
		"sudo -n -E bash -c 'echo %s | base64 -d | bash'",
	) {
		t.Fatal("repo-healer executor must run base64 decode inside non-interactive sudo")
	}
}
