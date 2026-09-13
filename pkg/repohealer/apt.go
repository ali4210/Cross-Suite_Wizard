package repohealer

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type APTAdapter struct{}

func (APTAdapter) Manager() PackageManager {
	return ManagerAPT
}

func (APTAdapter) Diagnose(
	exec Executor,
	facts TargetFacts,
	policy Policy,
) ([]CommandEvidence, []Finding, []RepairAction) {
	var evidence []CommandEvidence
	var findings []Finding
	var actions []RepairAction
	var aptListReferences []APTSourceReference

	seenKeyIDs := make(map[string]bool)
	seenMissingKeyrings := make(map[string]bool)

	runSudo := func(command string) string {
		started := time.Now()
		output, err := exec.RunSudo(command)

		exitCode := 0
		if err != nil {
			exitCode = 1
		}

		evidence = append(evidence, CommandEvidence{
			Command:  command,
			Output:   strings.TrimSpace(output),
			ExitCode: exitCode,
			Duration: time.Since(started),
		})

		return output
	}

	inventory := runSudo(`
set +e

echo '=== OS_RELEASE ==='
cat /etc/os-release 2>/dev/null

echo '=== ARCHITECTURE ==='
dpkg --print-architecture 2>/dev/null || uname -m

echo '=== INIT_SYSTEM ==='
ps -p 1 -o comm= 2>/dev/null

echo '=== APT_SOURCES ==='
grep -RIn --include='*.list' --include='*.sources' \
  -E '^[[:space:]]*(deb|Types:|URIs:|Suites:|Components:|Architectures:|Signed-By:)' \
  /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null

echo '=== SIGNED_BY_REFERENCES ==='
grep -RIn --include='*.list' --include='*.sources' \
  -E 'signed-by|Signed-By' \
  /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null

echo '=== DEB822_SOURCES ==='
find /etc/apt/sources.list.d -maxdepth 1 -type f -name '*.sources' -print0 2>/dev/null \
  | while IFS= read -r -d '' source_file; do
      printf '%s\n' '--- DEB822_FILE_BEGIN ---'
      printf '%s\n' "$source_file"
      cat "$source_file"
      printf '%s\n' '--- DEB822_FILE_END ---'
    done

echo '=== KEYRINGS ==='
find /etc/apt/keyrings /etc/apt/trusted.gpg.d \
  -maxdepth 1 -type f -printf '%p\t%m\t%u:%g\n' 2>/dev/null

echo '=== DPKG_AUDIT ==='
dpkg --audit 2>&1

echo '=== LOCK_OWNERS ==='
fuser -v /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
  /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>&1 || true

echo '=== STORAGE ==='
df -hT / 2>&1
findmnt -no TARGET,OPTIONS / 2>/dev/null || true

echo '=== TIME ==='
timedatectl status 2>&1 || true
`)

	updateOutput := runSudo(`
set +e
export DEBIAN_FRONTEND=noninteractive
apt-get update 2>&1
exit ${PIPESTATUS[0]}
`)

	noPubKeyPattern := regexp.MustCompile(`NO_PUBKEY[[:space:]]+([A-F0-9]+)`)
	for _, match := range noPubKeyPattern.FindAllStringSubmatch(updateOutput, -1) {
		keyID := strings.TrimSpace(match[1])
		if keyID == "" || seenKeyIDs[keyID] {
			continue
		}
		seenKeyIDs[keyID] = true

		findings = append(findings, Finding{
			Code:            "APT_REPO_KEY_MISSING",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        fmt.Sprintf("apt-get update reported NO_PUBKEY %s.", keyID),
			RecommendedFix:  "Identify the repository using this key, match it to a verified vendor profile, and restore only the pinned repository-specific keyring. Never retrieve an unknown key solely from a public keyserver.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	handleReference := func(reference APTSourceReference) {
		sourceFile := reference.SourceFile
		lineNumber := reference.LineNumber
		keyringPath := reference.KeyringPath

		dedupKey := fmt.Sprintf("%s:%d:%s", sourceFile, lineNumber, keyringPath)
		if sourceFile == "" || keyringPath == "" || seenMissingKeyrings[dedupKey] {
			return
		}
		seenMissingKeyrings[dedupKey] = true

		keyringCheck := fmt.Sprintf(`[ -r %q ] && echo PRESENT || echo MISSING`, keyringPath)
		keyringOutput := runSudo(keyringCheck)
		keyringMissing := strings.Contains(keyringOutput, "MISSING")

		repositoryURL := reference.RepositoryURL
		repositoryName := repositoryNameFromURL(repositoryURL)

		if !keyringMissing {
			profile, knownVendor := FindVendorProfile(ManagerAPT, repositoryURL)
			if knownVendor && !HasExpectedAPTKeyringBinding(profile, reference.SourceLine) {
				findings = append(findings, Finding{
					Code:           "APT_SOURCE_KEYRING_MISMATCH",
					Severity:       SeverityError,
					Risk:           RiskKnownVendor,
					RepositoryName: profile.DisplayName,
					RepositoryURL:  repositoryURL,
					SourceFile:     sourceFile,
					SourceLine:     lineNumber,
					Evidence: fmt.Sprintf(
						"Repository source binds %s to %s, but the verified profile requires %s.",
						profile.DisplayName,
						keyringPath,
						profile.KeyringPath,
					),
					RecommendedFix: fmt.Sprintf(
						"After explicit approval, restore only the verified %s keyring and rewrite %s with the profile-scoped signed-by binding.",
						profile.DisplayName,
						profile.SourceFile,
					),
					AutoRepairable:  true,
					RequiresConsent: true,
				})
			}
			return
		}

		finding := Finding{
			Code:            "APT_KEYRING_PATH_MISSING",
			Severity:        SeverityError,
			Risk:            RiskManual,
			RepositoryName:  repositoryName,
			RepositoryURL:   repositoryURL,
			SourceFile:      sourceFile,
			SourceLine:      lineNumber,
			Evidence:        fmt.Sprintf("Repository configuration references a missing or unreadable keyring: %s.", keyringPath),
			RecommendedFix:  "Restore the keyring only through a verified vendor profile, then bind the repository with signed-by to a dedicated keyring.",
			AutoRepairable:  false,
			RequiresConsent: true,
		}

		if profile, knownVendor := FindVendorProfile(ManagerAPT, repositoryURL); knownVendor {
			finding.RepositoryName = profile.DisplayName
			finding.Risk = RiskKnownVendor
			finding.AutoRepairable = true
			finding.RequiresConsent = true
			finding.RecommendedFix = fmt.Sprintf(
				"A verified %s profile can restore the dedicated keyring and rewrite only %s. The repair plan is shown separately and requires explicit approval before any system change.",
				profile.DisplayName,
				profile.SourceFile,
			)
		}

		findings = append(findings, finding)
	}

	for _, inventoryLine := range strings.Split(inventory, "\n") {
		reference, ok := ParseAPTListSourceReference(inventoryLine)
		if !ok {
			continue
		}
		aptListReferences = append(aptListReferences, reference)
		handleReference(reference)
	}

	for _, document := range ParseAPTDeb822Inventory(inventory) {
		for _, stanza := range document.Stanzas {
			reference, ok := ParseAPTDeb822SourceReference(
				document.SourceFile,
				stanza.StartLine,
				stanza.Content,
			)
			if !ok {
				continue
			}
			handleReference(reference)
		}
	}

	lowerUpdate := strings.ToLower(updateOutput)
	lowerInventory := strings.ToLower(inventory)

	if strings.Contains(lowerUpdate, "does not have a release file") || strings.Contains(lowerUpdate, "no release file") {
		findings = append(findings, Finding{
			Code:            "APT_REPO_RELEASE_MISSING",
			Severity:        SeverityError,
			Risk:            RiskApprovalNeeded,
			Evidence:        "apt-get update reported a repository without valid Release metadata.",
			RecommendedFix:  "Validate the vendor-supported repository URL and target suite. Do not disable apt-secure and do not automatically change distribution codenames.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	if strings.Contains(lowerUpdate, "could not get lock") {
		findings = append(findings, Finding{
			Code:            "APT_LOCK_ACTIVE",
			Severity:        SeverityWarning,
			Risk:            RiskAutoSafe,
			Evidence:        "APT reported an active package-manager lock.",
			RecommendedFix:  "Inspect the lock owner and wait for a legitimate active transaction. Never delete lock files while a package-manager process is running.",
			AutoRepairable:  true,
			RequiresConsent: false,
		})
	}

	if strings.Contains(lowerUpdate, "temporary failure resolving") || strings.Contains(lowerUpdate, "could not resolve") {
		findings = append(findings, Finding{
			Code:            "APT_REPO_DNS_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskManual,
			Evidence:        "APT could not resolve one or more repository hostnames.",
			RecommendedFix:  "Diagnose DNS, network reachability, proxy configuration, VPN, or local resolver state before changing repository configuration.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	if strings.Contains(lowerUpdate, "certificate verification failed") ||
		strings.Contains(lowerUpdate, "certificate is not trusted") ||
		strings.Contains(lowerUpdate, "tls") {
		findings = append(findings, Finding{
			Code:            "APT_REPO_TLS_FAILURE",
			Severity:        SeverityError,
			Risk:            RiskBlocked,
			Evidence:        "APT reported a TLS or certificate-validation failure.",
			RecommendedFix:  "Validate system time, CA certificates, proxy/TLS inspection policy, and repository ownership. Never disable TLS certificate verification as a repair.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	if strings.Contains(lowerInventory, " ro,") || strings.Contains(lowerInventory, "read-only") {
		findings = append(findings, Finding{
			Code:            "FILESYSTEM_READ_ONLY",
			Severity:        SeverityCritical,
			Risk:            RiskBlocked,
			Evidence:        "Root filesystem mount options or diagnostics indicate a read-only state.",
			RecommendedFix:  "Repair filesystem or storage health before attempting repository repair.",
			AutoRepairable:  false,
			RequiresConsent: true,
		})
	}

	if strings.Contains(lowerUpdate, "dpkg was interrupted") {
		findings = append(findings, Finding{
			Code:            "DPKG_INTERRUPTED",
			Severity:        SeverityError,
			Risk:            RiskAutoSafe,
			Evidence:        "APT reported that dpkg was interrupted.",
			RecommendedFix:  "After confirming no active package transaction exists, run controlled dpkg recovery and verify package database health.",
			AutoRepairable:  true,
			RequiresConsent: false,
		})
	}

	if strings.TrimSpace(updateOutput) == "" {
		findings = append(findings, Finding{
			Code:            "APT_DIAGNOSTIC_INCOMPLETE",
			Severity:        SeverityWarning,
			Risk:            RiskManual,
			Evidence:        "APT returned no diagnostic output; remote command execution or sudo may be incomplete.",
			RecommendedFix:  "Confirm SSH transport and sudo execution, then rerun diagnostics.",
			AutoRepairable:  false,
			RequiresConsent: false,
		})
	}

	actions = append(
		actions,
		BuildAPTListDoctorActions(
			Result{
				Target:   facts,
				Findings: findings,
			},
			aptListReferences,
		)...,
	)

	return evidence, findings, actions
}

type APTDeb822InventoryDocument struct {
	SourceFile string
	Stanzas    []APTDeb822InventoryStanza
}

type APTDeb822InventoryStanza struct {
	StartLine int
	Content   string
}

func ParseAPTDeb822Inventory(inventory string) []APTDeb822InventoryDocument {
	const beginMarker = "--- DEB822_FILE_BEGIN ---"
	const endMarker = "--- DEB822_FILE_END ---"

	var documents []APTDeb822InventoryDocument
	lines := strings.Split(inventory, "\n")

	for index := 0; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) != beginMarker {
			continue
		}

		index++
		if index >= len(lines) {
			break
		}

		sourceFile := strings.TrimSpace(lines[index])
		if sourceFile == "" {
			continue
		}

		var contentLines []string
		for index++; index < len(lines); index++ {
			if strings.TrimSpace(lines[index]) == endMarker {
				break
			}
			contentLines = append(contentLines, lines[index])
		}

		stanzas := splitAPTDeb822Stanzas(strings.Join(contentLines, "\n"))
		documents = append(documents, APTDeb822InventoryDocument{
			SourceFile: sourceFile,
			Stanzas:    stanzas,
		})
	}

	return documents
}

func splitAPTDeb822Stanzas(content string) []APTDeb822InventoryStanza {
	var stanzas []APTDeb822InventoryStanza
	lines := strings.Split(content, "\n")

	startLine := 1
	var current []string

	flush := func() {
		stanza := strings.TrimSpace(strings.Join(current, "\n"))
		if stanza == "" {
			return
		}
		stanzas = append(stanzas, APTDeb822InventoryStanza{
			StartLine: startLine,
			Content:   stanza,
		})
	}

	for lineIndex, line := range lines {
		if strings.TrimSpace(line) == "" {
			flush()
			current = nil
			startLine = lineIndex + 2
			continue
		}
		current = append(current, line)
	}

	flush()
	return stanzas
}

func extractRepositoryURL(sourceLine string) string {
	urlPattern := regexp.MustCompile(`https?://[^[:space:]]+`)
	return urlPattern.FindString(sourceLine)
}

func repositoryNameFromURL(repositoryURL string) string {
	switch {
	case isMicrosoftVSCodeRepo(repositoryURL):
		return "Microsoft Visual Studio Code"
	case strings.Contains(repositoryURL, "download.docker.com"):
		return "Docker"
	case strings.Contains(repositoryURL, "apt.releases.hashicorp.com"):
		return "HashiCorp"
	case strings.Contains(repositoryURL, "packages.wazuh.com"):
		return "Wazuh"
	case strings.Contains(repositoryURL, "pkgs.k8s.io") || strings.Contains(repositoryURL, "packages.k8s.io"):
		return "Kubernetes"
	case strings.Contains(repositoryURL, "apt.puppet.com"):
		return "Puppet"
	default:
		return "Unidentified APT Repository"
	}
}

func isMicrosoftVSCodeRepo(repositoryURL string) bool {
	return strings.HasPrefix(repositoryURL, "https://packages.microsoft.com/repos/code")
}
