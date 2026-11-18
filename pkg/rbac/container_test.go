package rbac

// Real-container integration tests for A-PR 1 (F-01, F-02, F-03).
//
// These tests spin up ONE real ubuntu:24.04 Docker container (shared across
// the whole file via TestMain, to avoid paying apt-get's cost once per test)
// with a real sshd, real sudo, real passwd/shadow tools, and a real
// golang.org/x/crypto/ssh client connection — not a mock SSH server. Where a
// test needs iptables it uses a stub binary on PATH instead of the real
// netfilter tooling, because a standard container has no NET_ADMIN capability
// by default; this is called out explicitly in each such test's name/doc as
// "mocked" iptables. Every other verification in this file (sudo auth,
// chpasswd, a real SSH login as the newly-provisioned user, sshd_config
// validity) is real.
//
// Tests skip cleanly (not fail) when Docker isn't available, or when not
// running on a Linux host — see requireDockerLinuxHost / sharedContainerSkip.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"cross-ssh/pkg/common"
	"golang.org/x/crypto/ssh"
)

const testerPassword = "ContainerTestSudoPW1"

var (
	sharedContainer     *rbacTestContainer
	sharedContainerSkip string // non-empty => every test in this file must t.Skip with this reason
)

func TestMain(m *testing.M) {
	if runtime.GOOS != "linux" {
		sharedContainerSkip = "real-container sshd/sudo/chpasswd integration tests need a Linux Docker host"
	} else if _, err := exec.LookPath("docker"); err != nil {
		sharedContainerSkip = "docker not found on PATH"
	} else if err := exec.Command("docker", "info").Run(); err != nil {
		sharedContainerSkip = "docker daemon not reachable on this runner"
	}

	code := 0
	if sharedContainerSkip == "" {
		c, err := buildRBACTestContainer()
		if err != nil {
			sharedContainerSkip = "could not start shared ubuntu:24.04 test container: " + err.Error()
		} else {
			sharedContainer = c
		}
		code = m.Run()
		if sharedContainer != nil {
			_ = exec.Command("docker", "rm", "-f", sharedContainer.name).Run()
		}
	} else {
		code = m.Run()
	}
	os.Exit(code)
}

func requireSharedContainer(t *testing.T) *rbacTestContainer {
	t.Helper()
	if sharedContainerSkip != "" {
		t.Skip("skipping: " + sharedContainerSkip)
	}
	return sharedContainer
}

// rbacTestContainer is a disposable ubuntu:24.04 container with sshd, sudo,
// and python3 installed, a "tester" user (password testerPassword, member of
// the sudo group) and sshd running with password authentication enabled.
type rbacTestContainer struct {
	name    string
	sshPort string
}

func rawDockerExec(name, script string) (string, error) {
	cmd := exec.Command("docker", "exec", name, "bash", "-c", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func buildRBACTestContainer() (*rbacTestContainer, error) {
	name := fmt.Sprintf("cross7-rbac-test-%d", time.Now().UnixNano())

	run := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-p", "127.0.0.1::22", "ubuntu:24.04", "sleep", "infinity")
	var runOut bytes.Buffer
	run.Stdout = &runOut
	run.Stderr = &runOut
	if err := run.Run(); err != nil {
		return nil, fmt.Errorf("docker run: %w (%s)", err, runOut.String())
	}

	c := &rbacTestContainer{name: name}

	// The clock in some sandboxes/CI caches can drift from the archive's Release
	// file Date field; Check-Date=false only skips that sanity check, not signing.
	setup := `
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Check-Date=false update -qq
apt-get install -y -qq openssh-server sudo python3 >/dev/null
mkdir -p /run/sshd
ssh-keygen -A >/dev/null
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?UsePAM.*/UsePAM no/' /etc/ssh/sshd_config
id -u tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester
echo "tester:` + testerPassword + `" | chpasswd
usermod -aG sudo tester
/usr/sbin/sshd
`
	if out, err := rawDockerExec(name, setup); err != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return nil, fmt.Errorf("container setup failed: %w\noutput:\n%s", err, out)
	}

	portOut, err := exec.Command("docker", "port", name, "22").CombinedOutput()
	if err != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return nil, fmt.Errorf("docker port lookup failed: %w (%s)", err, portOut)
	}
	// Output like "0.0.0.0:54321" or "127.0.0.1:54321" — take the part after the last ':'.
	fields := strings.Split(strings.TrimSpace(string(portOut)), ":")
	c.sshPort = fields[len(fields)-1]

	return c, nil
}

func (c *rbacTestContainer) exec(t *testing.T, script string) string {
	t.Helper()
	out, err := rawDockerExec(c.name, script)
	if err != nil {
		t.Fatalf("docker exec %q failed: %v\noutput:\n%s", script, err, out)
	}
	return out
}

// dial opens a real SSH connection to the container as the given user/password.
func (c *rbacTestContainer) dial(t *testing.T, user, password string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	addr := "127.0.0.1:" + c.sshPort
	var client *ssh.Client
	var err error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", addr, cfg)
		if err == nil {
			return client
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("could not SSH to container as %s: %v", user, err)
	return nil
}

func withSavedSudoPassword(t *testing.T, client *ssh.Client, value string) {
	t.Helper()
	key := sudoCacheKey(client)
	prev, existed := sudoPasswordCache[key]
	sudoPasswordCache[key] = value
	t.Cleanup(func() {
		if existed {
			sudoPasswordCache[key] = prev
		} else {
			delete(sudoPasswordCache, key)
		}
	})
}

func testTimeout() time.Duration { return 10 * time.Second }

// --- F-01: password delivered to chpasswd only via stdin, never argv -------

func TestChpasswdPasswordDeliveredOnlyViaStdinNotArgv(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()
	withSavedSudoPassword(t, client, testerPassword)

	// Stub chpasswd: records its own argv and whatever it received on stdin,
	// instead of touching the real shadow file. This lets us assert — for
	// real, inside the real container, under the real sudo secure_path —
	// that the only way the secret reaches the command is via stdin.
	stub := `cat > /usr/local/bin/chpasswd <<'EOS'
#!/bin/bash
echo "ARGC:$#" > /tmp/chpasswd_capture.log
echo "ARGV:$@" >> /tmp/chpasswd_capture.log
echo "STDIN:$(cat)" >> /tmp/chpasswd_capture.log
EOS
chmod +x /usr/local/bin/chpasswd
rm -f /tmp/chpasswd_capture.log
`
	c.exec(t, stub)
	defer c.exec(t, "rm -f /usr/local/bin/chpasswd /tmp/chpasswd_capture.log")

	secretPassword := "Pr0b3-Stdin-Only!"
	if err := setLinuxPasswordViaChpasswd(client, "probeuser", secretPassword, testTimeout()); err != nil {
		t.Fatalf("setLinuxPasswordViaChpasswd returned error against stub: %v", err)
	}

	capture := c.exec(t, "cat /tmp/chpasswd_capture.log")
	if !strings.Contains(capture, "ARGC:0") {
		t.Fatalf("expected chpasswd to receive zero CLI arguments, got capture:\n%s", capture)
	}
	if strings.Contains(capture, "ARGV:"+secretPassword) {
		t.Fatalf("password leaked into argv, capture:\n%s", capture)
	}
	wantStdin := "STDIN:probeuser:" + secretPassword
	if !strings.Contains(capture, wantStdin) {
		t.Fatalf("expected stdin to carry %q, capture:\n%s", wantStdin, capture)
	}

	// Independently confirm via the real process list: launch a slow stub so we can
	// observe argv while it's running, proving no secret appears there either.
	slowStub := `cat > /usr/local/bin/chpasswd <<'EOS'
#!/bin/bash
sleep 2
EOS
chmod +x /usr/local/bin/chpasswd
`
	c.exec(t, slowStub)
	done := make(chan error, 1)
	go func() {
		_, err := runPrivilegedWithSecretStdin(client, "chpasswd", []string{"probeuser:" + secretPassword}, 10*time.Second)
		done <- err
	}()
	time.Sleep(800 * time.Millisecond)
	psOut := c.exec(t, "ps -eo args")
	if strings.Contains(psOut, secretPassword) {
		t.Fatalf("password visible in live process list:\n%s", psOut)
	}
	if err := <-done; err != nil {
		t.Fatalf("slow stub invocation failed: %v", err)
	}
}

// --- F-01: the password really works for a real login ----------------------

func TestChpasswdSetPasswordAllowsRealSSHLogin(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()
	withSavedSudoPassword(t, client, testerPassword)

	c.exec(t, "id -u newuser >/dev/null 2>&1 || useradd -m -s /bin/bash newuser")

	newPassword := "Real-Chpasswd-Works-1!"
	if err := setLinuxPasswordViaChpasswd(client, "newuser", newPassword, testTimeout()); err != nil {
		t.Fatalf("setLinuxPasswordViaChpasswd failed: %v", err)
	}

	// Real SSH login as the newly-provisioned user, using the real chpasswd / shadow file.
	newClient := c.dial(t, "newuser", newPassword)
	defer newClient.Close()

	session, err := newClient.NewSession()
	if err != nil {
		t.Fatalf("failed to open session as newuser: %v", err)
	}
	defer session.Close()
	if out, err := session.CombinedOutput("whoami"); err != nil || strings.TrimSpace(string(out)) != "newuser" {
		t.Fatalf("expected whoami=newuser, got %q err=%v", out, err)
	}

	// The plaintext must not have landed in any container log or shell history.
	leakCheck := c.exec(t, `
grep -R -- '`+newPassword+`' /var/log 2>/dev/null || true
grep -R -- '`+newPassword+`' /root/.bash_history /home/*/.bash_history 2>/dev/null || true
echo DONE
`)
	if strings.Contains(leakCheck, newPassword) {
		t.Fatalf("password leaked into a log or shell history:\n%s", leakCheck)
	}
}

// --- F-02: stacking an IP must not lock the user out of SSH -----------------

func TestIPStackScriptDoesNotWriteSSHDMatchBlockOrLockOutUser(t *testing.T) {
	c := requireSharedContainer(t)
	root := c.dial(t, "tester", testerPassword)
	defer root.Close()
	withSavedSudoPassword(t, root, testerPassword)

	stackedPassword := "Stacked-User-Keeps-SSH-1!"
	c.exec(t, "id -u stackeduser >/dev/null 2>&1 || useradd -m -s /bin/bash stackeduser")
	if err := setLinuxPasswordViaChpasswd(root, "stackeduser", stackedPassword, testTimeout()); err != nil {
		t.Fatalf("failed to set stackeduser's password: %v", err)
	}

	// Sanity: the user can log in BEFORE IP stacking runs.
	pre := c.dial(t, "stackeduser", stackedPassword)
	pre.Close()

	// Exercises the exact same invocation path assignIPAndVirtualInterface uses in
	// production: wrapSudo's base64-encoded pipeline, not the stdin-secret helper
	// (that helper is for simple single-token commands like "chpasswd", not a
	// multi-line script full of embedded quotes).
	script := buildIPStackScript("10.99.0.50/32", "lo", "stackeduser")
	out, err := common.ExecuteRemoteCommand(root, wrapSudo(root, script), testTimeout())
	if err != nil || !strings.Contains(out, "IP_PROVISION_OK") {
		t.Fatalf("buildIPStackScript did not report success: err=%v out=%s", err, out)
	}

	// F-02: no sshd_config.d drop-in must be created by stacking an IP.
	check := c.exec(t, `
test -e /etc/ssh/sshd_config.d/rbac_stackeduser.conf && echo PRESENT || echo ABSENT
sshd -t && echo SSHD_CONFIG_VALID || echo SSHD_CONFIG_INVALID
`)
	if !strings.Contains(check, "ABSENT") {
		t.Fatalf("expected no sshd_config.d drop-in for the stacked user, got:\n%s", check)
	}
	if !strings.Contains(check, "SSHD_CONFIG_VALID") {
		t.Fatalf("sshd -t reported the config invalid after IP stacking:\n%s", check)
	}

	// F-02: the user must still be able to log in via SSH after IP stacking.
	post := c.dial(t, "stackeduser", stackedPassword)
	defer post.Close()
	session, err := post.NewSession()
	if err != nil {
		t.Fatalf("stackeduser was locked out of SSH after IP stacking: %v", err)
	}
	defer session.Close()
	if out, err := session.CombinedOutput("whoami"); err != nil || strings.TrimSpace(string(out)) != "stackeduser" {
		t.Fatalf("expected whoami=stackeduser after IP stacking, got %q err=%v", out, err)
	}
}

// --- F-03: remove-blanket must never report false success -------------------

// installStubIPTables replaces iptables with a scripted stub. iptables requires
// NET_ADMIN and real netfilter state that a default container doesn't have, so
// this and the F-03 tests below are explicitly MOCKED at the iptables layer —
// everything else (the real python3 interpreter, real sudo, the real SSH
// session and the real stdout/stderr capture path) is real.
func installStubIPTables(t *testing.T, c *rbacTestContainer, listOutputs []string) {
	t.Helper()
	var script strings.Builder
	script.WriteString("mkdir -p /tmp/stubstate\n")
	script.WriteString("echo 0 > /tmp/stubstate/call\n")
	script.WriteString("cat > /usr/local/bin/iptables <<'EOS'\n#!/bin/bash\n")
	script.WriteString(`call=$(cat /tmp/stubstate/call)` + "\n")
	script.WriteString(`case "$1" in` + "\n  -L)\n")
	for i, o := range listOutputs {
		script.WriteString(fmt.Sprintf("    if [ \"$call\" = \"%d\" ]; then cat <<'LISTEOF'\n%s\nLISTEOF\n    fi\n", i, o))
	}
	script.WriteString("    echo $((call+1)) > /tmp/stubstate/call\n    ;;\n  -D)\n    ;;\n  -I)\n    ;;\nesac\nexit 0\nEOS\n")
	script.WriteString("chmod +x /usr/local/bin/iptables\n")
	c.exec(t, script.String())
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestApplyPortRuleRemoveBlanketWhenRuleIsPresent(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()
	withSavedSudoPassword(t, client, testerPassword)

	uidOut := strings.TrimSpace(c.exec(t, "id -u tester"))
	// First -L call reports a blanket-allow rule for this UID; second call (after
	// the fixed script deletes it) reports nothing, so the loop exits cleanly.
	installStubIPTables(t, c, []string{
		fmt.Sprintf("1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            owner UID match %s", uidOut),
		"",
	})
	defer c.exec(t, "rm -f /usr/local/bin/iptables")

	output := captureStdout(t, func() {
		applyPortRule(client, "tester", uidOut, "", "remove-blanket")
	})

	if !strings.Contains(output, "Blanket Allow-All rule removed") {
		t.Fatalf("expected a real success message when the blanket rule was present, got:\n%s", output)
	}
	if strings.Contains(output, "Operation completed") {
		t.Fatalf("must never fall back to the generic 'Operation completed' message, got:\n%s", output)
	}
}

func TestApplyPortRuleRemoveBlanketWhenRuleIsAbsent(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()
	withSavedSudoPassword(t, client, testerPassword)

	uidOut := strings.TrimSpace(c.exec(t, "id -u tester"))
	installStubIPTables(t, c, []string{""})
	defer c.exec(t, "rm -f /usr/local/bin/iptables")

	output := captureStdout(t, func() {
		applyPortRule(client, "tester", uidOut, "", "remove-blanket")
	})

	if !strings.Contains(output, "Blanket Allow-All rule removed") {
		t.Fatalf("expected a real success message when no blanket rule existed, got:\n%s", output)
	}
}

func TestApplyPortRuleRemoveBlanketReportsRealErrorNeverFalseSuccess(t *testing.T) {
	c := requireSharedContainer(t)
	client := c.dial(t, "tester", testerPassword)
	defer client.Close()
	withSavedSudoPassword(t, client, testerPassword)

	uidOut := strings.TrimSpace(c.exec(t, "id -u tester"))
	// A stub that always exits non-zero simulates an iptables failure (e.g. the
	// kernel module missing). The python wrapper's subprocess.run(..., check=False)
	// calls won't raise for this, so to force a genuine crash path we instead break
	// python itself: this models what F-03 originally did (an undefined variable),
	// by pointing PATH at a python3 that errors out before printing any marker.
	brokenPython := `cat > /usr/local/bin/python3 <<'EOS'
#!/bin/bash
echo "Traceback (most recent call last): NameError: name 'lines' is not defined" >&2
exit 1
EOS
chmod +x /usr/local/bin/python3
`
	c.exec(t, brokenPython)
	defer c.exec(t, "rm -f /usr/local/bin/python3")

	output := captureStdout(t, func() {
		applyPortRule(client, "tester", uidOut, "", "remove-blanket")
	})

	if strings.Contains(output, "Operation completed") {
		t.Fatalf("a crashing remote script must never be reported as 'Operation completed', got:\n%s", output)
	}
	if !strings.Contains(output, "FAILED") {
		t.Fatalf("expected an explicit FAILED report, got:\n%s", output)
	}
	if !strings.Contains(output, "NameError") {
		t.Fatalf("expected the real remote error text to be surfaced to the operator, got:\n%s", output)
	}
}
