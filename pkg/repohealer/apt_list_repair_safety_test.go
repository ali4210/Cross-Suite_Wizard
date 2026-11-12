package repohealer

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func safeNetworkFactsProbeOutput() string {
	return fmt.Sprintf(
		"=== DNS ===\n%s\n=== PROXY ===\n=== CLOCK ===\n%d\n=== DISK ===\n/dev/sda1 20971520 2097152 18874368 10%% /\n",
		"github.com has address 140.82.121.4",
		time.Now().UTC().Unix(),
	)
}

func diskFullNetworkFactsProbeOutput() string {
	return fmt.Sprintf(
		"=== DNS ===\n%s\n=== PROXY ===\n=== CLOCK ===\n%d\n=== DISK ===\n/dev/sda1 20971520 20771520 200 99%% /\n",
		"github.com has address 140.82.121.4",
		time.Now().UTC().Unix(),
	)
}

func clockSkewedNetworkFactsProbeOutput() string {
	skewed := time.Now().UTC().Add(-1 * time.Hour).Unix()
	return fmt.Sprintf(
		"=== DNS ===\n%s\n=== PROXY ===\n=== CLOCK ===\n%d\n=== DISK ===\n/dev/sda1 20971520 2097152 18874368 10%% /\n",
		"github.com has address 140.82.121.4",
		skewed,
	)
}

func TestEvaluateHashiCorpAPTListRepairSafetyHealthy(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs:     []string{safeNetworkFactsProbeOutput()},
		runSudoOutputs: []string{""},
	}

	safety := EvaluateHashiCorpAPTListRepairSafety(exec)

	if blocked, reason := safety.Blocked(); blocked {
		t.Fatalf("healthy target unexpectedly blocked: %s", reason)
	}
}

func TestEvaluateHashiCorpAPTListRepairSafetyBlocksOnLowDiskSpace(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs:     []string{diskFullNetworkFactsProbeOutput()},
		runSudoOutputs: []string{""},
	}

	safety := EvaluateHashiCorpAPTListRepairSafety(exec)

	blocked, reason := safety.Blocked()
	if !blocked {
		t.Fatal("low disk space must block the repair")
	}
	if !strings.Contains(strings.ToLower(reason), "disk") {
		t.Fatalf("reason should explain the disk space problem, got: %s", reason)
	}
	if !strings.Contains(reason, "Next step:") {
		t.Fatalf("reason should include a plain-language next step, got: %s", reason)
	}
}

func TestEvaluateHashiCorpAPTListRepairSafetyBlocksOnClockSkew(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs:     []string{clockSkewedNetworkFactsProbeOutput()},
		runSudoOutputs: []string{""},
	}

	safety := EvaluateHashiCorpAPTListRepairSafety(exec)

	blocked, reason := safety.Blocked()
	if !blocked {
		t.Fatal("suspected clock skew must block the repair")
	}
	if !strings.Contains(strings.ToLower(reason), "clock") {
		t.Fatalf("reason should explain the clock skew problem, got: %s", reason)
	}
}

func TestEvaluateHashiCorpAPTListRepairSafetyBlocksOnBrokenDpkg(t *testing.T) {
	exec := &fakeExecutor{
		runOutputs: []string{safeNetworkFactsProbeOutput()},
		runSudoOutputs: []string{
			"libfoo:amd64 missing conffile /etc/foo.conf\nbar is unpacked but not configured",
		},
	}

	safety := EvaluateHashiCorpAPTListRepairSafety(exec)

	blocked, reason := safety.Blocked()
	if !blocked {
		t.Fatal("a broken dpkg database must block the repair")
	}
	if !strings.Contains(reason, "libfoo") {
		t.Fatalf("reason should include the actual dpkg --audit output, got: %s", reason)
	}
	if !strings.Contains(reason, "fix-broken install") {
		t.Fatalf("reason should point at the gated fix-broken-install repair, got: %s", reason)
	}
}

func TestHashiCorpAPTListRepairSafetyBlockedPrecedenceDiskFirst(t *testing.T) {
	safety := HashiCorpAPTListRepairSafety{
		DiskSpaceLow:       true,
		DiskEvidence:       "disk is full",
		ClockSkewSuspected: true,
		ClockEvidence:      "clock is skewed",
		DpkgBroken:         true,
		DpkgAuditOutput:    "broken package",
	}

	blocked, reason := safety.Blocked()
	if !blocked {
		t.Fatal("expected a block")
	}
	if !strings.Contains(strings.ToLower(reason), "disk") {
		t.Fatalf("expected disk space to take precedence, got: %s", reason)
	}
}
