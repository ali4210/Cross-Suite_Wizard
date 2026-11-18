package rbac

// Tests for A-PR 2 (F-05, F-06, F-07, F-10).
//
// F-05 and F-06 run against the real shared container (real sshd, real
// ssh.Client.User()). F-07 combines pure-function unit tests of the input
// validator with a real-container test of the atomic sudoers install script,
// including hostile input that would have been a shell-injection vector
// under the pre-fix code. F-10 combines a direct unit test of the audit log
// writer with a static AST-based safety net over every auditLog call site in
// rbac.go, so a future change that accidentally logs a password is caught by
// `go test` without needing to execute every call site.

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cross-ssh/pkg/common"
)

// --- F-05: confinement preview + typed confirmation + self-lockout guard ---

func TestConfirmConfinementActionCancelsOnEmptyInput(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()

	reader := bufio.NewReader(strings.NewReader("\n"))
	ok := confirmConfinementAction(reader, client, "someotheruser", "Block Local LAN", "preview text")
	if ok {
		t.Fatal("expected cancellation on empty input for a non-self target")
	}
}

func TestConfirmConfinementActionAppliesOnTypedConfirm(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()

	reader := bufio.NewReader(strings.NewReader("CONFIRM\n"))
	ok := confirmConfinementAction(reader, client, "someotheruser", "Block Local LAN", "preview text")
	if !ok {
		t.Fatal("expected approval when the operator types CONFIRM for a non-self target")
	}
}

func TestConfirmConfinementActionRequiresExtraPhraseWhenTargetingSelf(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword) // authenticated AS "tester"
	defer client.Close()

	// The ordinary "CONFIRM" phrase must NOT be enough when the selected user is
	// the one this very SSH session is authenticated as.
	reader := bufio.NewReader(strings.NewReader("CONFIRM\n"))
	if confirmConfinementAction(reader, client, "tester", "Complete Network Blackhole", "preview text") {
		t.Fatal("'CONFIRM' alone must not be accepted when the target is the session's own user")
	}

	reader2 := bufio.NewReader(strings.NewReader("LOCK MYSELF OUT\n"))
	if !confirmConfinementAction(reader2, client, "tester", "Complete Network Blackhole", "preview text") {
		t.Fatal("expected approval once the operator types the exact self-lockout phrase")
	}
}

// --- F-06: elevation password cache is scoped per (host, user), never reused ---

func TestSudoCacheKeyDiffersByAuthenticatedUser(t *testing.T) {
	c := requireSharedContainer(t)
	c.exec(t, "id -u cachecheckuser >/dev/null 2>&1 || useradd -m -s /bin/bash cachecheckuser")
	clientA := c.dial(t, "tester", testerPassword)
	defer clientA.Close()
	if err := setLinuxPasswordViaChpasswdForSetup(t, c, "cachecheckuser", "CacheCheckPW1!"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	clientB := c.dial(t, "cachecheckuser", "CacheCheckPW1!")
	defer clientB.Close()

	keyA := sudoCacheKey(clientA)
	keyB := sudoCacheKey(clientB)
	if keyA == keyB {
		t.Fatalf("expected distinct cache keys for distinct authenticated users, got identical key %q for both", keyA)
	}
}

func TestWrapSudoNeverAppliesAnotherHostsCachedPassword(t *testing.T) {
	c := requireSharedContainer(t)
	c.exec(t, "id -u cacheisouser >/dev/null 2>&1 || useradd -m -s /bin/bash cacheisouser")
	clientA := c.dial(t, "tester", testerPassword)
	defer clientA.Close()
	if err := setLinuxPasswordViaChpasswdForSetup(t, c, "cacheisouser", "CacheIsoPW1!"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	clientB := c.dial(t, "cacheisouser", "CacheIsoPW1!")
	defer clientB.Close()

	keyA := sudoCacheKey(clientA)
	keyB := sudoCacheKey(clientB)
	prevA, hadA := sudoPasswordCache[keyA]
	prevB, hadB := sudoPasswordCache[keyB]
	t.Cleanup(func() {
		if hadA {
			sudoPasswordCache[keyA] = prevA
		} else {
			delete(sudoPasswordCache, keyA)
		}
		if hadB {
			sudoPasswordCache[keyB] = prevB
		} else {
			delete(sudoPasswordCache, keyB)
		}
	})

	delete(sudoPasswordCache, keyB)
	sudoPasswordCache[keyA] = "clientA-password-only"

	// clientB has no cache entry of its own, so wrapSudo must return the command
	// completely unwrapped — it must never fall back to clientA's password.
	unwrapped := wrapSudo(clientB, "echo hi")
	if unwrapped != "echo hi" {
		t.Fatalf("expected clientB's wrapSudo to apply no elevation at all, got: %s", unwrapped)
	}

	sudoPasswordCache[keyB] = "clientB-password-only"
	wrappedB := wrapSudo(clientB, "echo hi")
	if strings.Contains(wrappedB, "clientA-password-only") {
		t.Fatalf("clientB's wrapped command leaked clientA's cached password: %s", wrappedB)
	}
	if !strings.Contains(wrappedB, "clientB-password-only") {
		t.Fatalf("clientB's wrapped command did not use its own cached password: %s", wrappedB)
	}
}

func TestDropSudoCacheOnHostSwitchClearsStaleEntries(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()

	prevLastKey := lastSudoHostKey
	t.Cleanup(func() { lastSudoHostKey = prevLastKey })

	keyA := "fake-previous-host|someuser"
	sudoPasswordCache[keyA] = "stale-password-from-a-previous-target"
	lastSudoHostKey = keyA

	dropSudoCacheOnHostSwitch(client) // switching to the real container's key

	if _, stillPresent := sudoPasswordCache[keyA]; stillPresent {
		t.Fatal("expected the previous host's cached password to be dropped on a detected target switch")
	}
	if lastSudoHostKey != sudoCacheKey(client) {
		t.Fatalf("expected lastSudoHostKey to be updated to the new target, got %q", lastSudoHostKey)
	}
}

// --- F-07: Tier 5 custom sudoers path validation + atomic install script ---

func TestValidateCustomSudoersPathsAcceptsSimpleEntries(t *testing.T) {
	got, err := validateCustomSudoersPaths("/usr/bin/docker, /usr/bin/systemctl * mysql")
	if err != nil {
		t.Fatalf("expected valid entries to be accepted, got error: %v", err)
	}
	want := []string{"/usr/bin/docker", "/usr/bin/systemctl * mysql"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestValidateCustomSudoersPathsRejectsHostileEntries(t *testing.T) {
	hostile := []string{
		"/usr/bin/docker; rm -rf /",
		"/usr/bin/docker`whoami`",
		"/usr/bin/docker$(whoami)",
		"/usr/bin/docker\nrm -rf /",
		"/usr/bin/docker'",
		`/usr/bin/docker"`,
		"not-an-absolute-path",
		"/usr/bin/docker|cat /etc/shadow",
		"/usr/bin/docker && reboot",
	}
	for _, h := range hostile {
		if _, err := validateCustomSudoersPaths(h); err == nil {
			t.Errorf("expected %q to be rejected, but it was accepted", h)
		}
	}
}

func TestBuildSudoersInstallScriptAppliesValidatesBacksUpAndNeverExecutesHostileContent(t *testing.T) {
	c := requireSharedContainer(t)
	root := c.dial(t, "tester", testerPassword)
	defer root.Close()
	withSavedSudoPassword(t, root, testerPassword)

	username := "sudoersscripttestuser"
	c.exec(t, "id -u "+username+" >/dev/null 2>&1 || useradd -m -s /bin/bash "+username)
	c.exec(t, "rm -f /etc/sudoers.d/cross_rbac_"+username+" /etc/sudoers.d/.bak_rbac_"+username)

	// 1. A valid rule installs atomically with the right permissions and content.
	firstContent := username + " ALL=(ALL) /usr/bin/docker, /usr/bin/kubectl"
	script := buildSudoersInstallScript(username, firstContent)
	out, err := common.ExecuteRemoteCommand(root, wrapSudo(root, script), testTimeout())
	if err != nil || !strings.Contains(out, "VISUDO_SUCCESS") {
		t.Fatalf("expected the first valid rule to install, err=%v out=%s", err, out)
	}
	installed := strings.TrimSpace(c.exec(t, "cat /etc/sudoers.d/cross_rbac_"+username))
	if installed != firstContent {
		t.Fatalf("installed sudoers content = %q, want %q", installed, firstContent)
	}
	perms := strings.TrimSpace(c.exec(t, "stat -c %a /etc/sudoers.d/cross_rbac_"+username))
	if perms != "440" {
		t.Fatalf("expected mode 440 on the installed sudoers file, got %s", perms)
	}

	// 2. A second valid rule must back up the first before overwriting it.
	secondContent := username + " ALL=(ALL) /usr/bin/ss"
	script2 := buildSudoersInstallScript(username, secondContent)
	out2, err2 := common.ExecuteRemoteCommand(root, wrapSudo(root, script2), testTimeout())
	if err2 != nil || !strings.Contains(out2, "VISUDO_SUCCESS") {
		t.Fatalf("expected the second valid rule to install, err=%v out=%s", err2, out2)
	}
	backup := strings.TrimSpace(c.exec(t, "cat /etc/sudoers.d/.bak_rbac_"+username))
	if backup != firstContent {
		t.Fatalf("expected the backup to hold the FIRST rule's content %q, got %q", firstContent, backup)
	}
	installedAfter := strings.TrimSpace(c.exec(t, "cat /etc/sudoers.d/cross_rbac_"+username))
	if installedAfter != secondContent {
		t.Fatalf("installed sudoers content after second apply = %q, want %q", installedAfter, secondContent)
	}

	// 3. Hostile content (the kind validateCustomSudoersPaths now rejects before
	// this script ever runs) must never be executed by the shell even if it
	// somehow reached this script — only ever written verbatim via base64, then
	// parsed as sudoers syntax by visudo (which will reject it as garbage).
	c.exec(t, "rm -f /tmp/PWNED_F07_PROOF")
	hostileContent := username + " ALL=(ALL) ALL; touch /tmp/PWNED_F07_PROOF; echo `touch /tmp/PWNED_F07_PROOF2`"
	script3 := buildSudoersInstallScript(username, hostileContent)
	out3, _ := common.ExecuteRemoteCommand(root, wrapSudo(root, script3), testTimeout())
	proof := c.exec(t, "test -e /tmp/PWNED_F07_PROOF && echo PWNED || echo SAFE; test -e /tmp/PWNED_F07_PROOF2 && echo PWNED2 || echo SAFE2")
	if strings.Contains(proof, "PWNED") {
		t.Fatalf("hostile sudoers content was executed by the shell instead of only being parsed as sudoers syntax: %s (script output: %s)", proof, out3)
	}
	// visudo should also have rejected this as invalid syntax, so the previous
	// (second) rule must still be the one installed — nothing was overwritten.
	installedFinal := strings.TrimSpace(c.exec(t, "cat /etc/sudoers.d/cross_rbac_"+username))
	if installedFinal != secondContent {
		t.Fatalf("expected the sudoers file to be untouched after a rejected rule, got %q, want %q", installedFinal, secondContent)
	}
}

// --- F-10: audit logging never carries a secret ---

func TestAuditLogWritesExpectedFormatAndNoSecret(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	prevAlias := currentHostAlias
	currentHostAlias = "test-target-host"
	t.Cleanup(func() { currentHostAlias = prevAlias })

	auditLog("provision_identity", "user=someuser os=linux", "applied")

	data, err := os.ReadFile(filepath.Join(tmpDir, "compliance_audit.log"))
	if err != nil {
		t.Fatalf("expected compliance_audit.log to be written: %v", err)
	}
	line := string(data)
	for _, want := range []string{"host=test-target-host", "action=provision_identity", "result=applied", "detail=user=someuser os=linux"} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit log line missing %q, got: %s", want, line)
		}
	}
}

// TestNoAuditLogCallSiteReferencesAPasswordVariable is a static safety net, not a
// dynamic exploit test: it parses rbac.go's AST and checks every auditLog(...)
// call site's arguments for identifiers that look like secret material. It is
// meant to catch a future regression (someone adding `password` to a detail
// string) at `go test` time, not to prove every historical call site was safe —
// those were already reviewed by hand when F-10 was implemented.
func TestNoAuditLogCallSiteReferencesAPasswordVariable(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rbac.go", nil, 0)
	if err != nil {
		t.Fatalf("failed to parse rbac.go: %v", err)
	}

	// Only actual identifiers (variable/field names) are checked, never string
	// literal text — a detail string like "stage=set_password" is a safe static
	// label, not a reference to a secret-holding variable, and must not trip this.
	forbidden := map[string]bool{
		"password": true, "Password": true,
		"secret": true, "Secret": true,
		"localSudoPassword": true, "sudoPasswordCache": true,
		"pass": true, "Pass": true,
	}
	var violations []string

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "auditLog" {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(inner ast.Node) bool {
				id, ok := inner.(*ast.Ident)
				if !ok {
					return true
				}
				if forbidden[id.Name] {
					pos := fset.Position(id.Pos())
					var buf strings.Builder
					_ = format.Node(&buf, fset, arg)
					violations = append(violations, fmt.Sprintf("line %d: argument `%s` references forbidden identifier `%s`", pos.Line, buf.String(), id.Name))
				}
				return true
			})
		}
		return true
	})

	if len(violations) > 0 {
		t.Fatalf("found auditLog call site(s) that reference secret-looking identifiers:\n%s", strings.Join(violations, "\n"))
	}
}

// setLinuxPasswordViaChpasswdForSetup is a thin wrapper used only to provision a
// throwaway test user's password via docker exec (not the SSH path under test),
// kept separate from the real setLinuxPasswordViaChpasswd so F-06 tests don't
// depend on F-01's code path succeeding first.
func setLinuxPasswordViaChpasswdForSetup(t *testing.T, c *rbacTestContainer, username, password string) error {
	t.Helper()
	_, err := rawDockerExec(c.name, "echo '"+username+":"+password+"' | chpasswd")
	return err
}
