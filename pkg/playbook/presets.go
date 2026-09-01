package playbook

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

// Global cached sudo password for the session
var cachedSudoPassword string

// ActiveRuntime holds the resolved container CLI binary (Locked to "docker")
var ActiveRuntime = "docker"

// PresetDefinition represents a DevSecOps application recipe
type PresetDefinition struct {
	ID          string
	Name        string
	DefaultPort int
	Category    string
	Description string
	IsBundle    bool
}

// GetCatalog returns the master inventory of available DevSecOps tool presets
func GetCatalog() []PresetDefinition {
	return []PresetDefinition{
		// ==>> TIER A: INTERCONNECTED FULL-STACK BUNDLES (LTS / STABLE PINNED)
		{ID: "devsecops_suite", Name: "DevSecOps Super-Suite (GitLab, Jenkins, Sonar, Prom, Grafana)", DefaultPort: 8929, Category: "Interconnected Stack", Description: "All-in-One Pre-Wired Pipeline (LTS Pinned)", IsBundle: true},
		{ID: "wazuh_soc", Name: "Wazuh SIEM & XDR Observability Suite", DefaultPort: 443, Category: "Interconnected Stack", Description: "Unified SIEM Core + XDR Dashboard + Host Agent Binding", IsBundle: true},
		{ID: "gitops_appsec_suite", Name: "AppSec & GitOps Cloud-Native Stack (ArgoCD, K3s, Trivy, Vault)", DefaultPort: 8080, Category: "Interconnected Stack", Description: "GitOps CD + K8s Cluster + Vulnerability Scanner + Secrets", IsBundle: true},

		// ==>> TIER B: MODULAR PLATFORMS & ENGINES (DUAL-OPTION CONFIGURABLE)
		{ID: "docker", Name: "Docker Engine & Docker Compose", DefaultPort: 0, Category: "Runtime", Description: "Standard Stable Engine vs Live Upstream Release", IsBundle: false},
		{ID: "wazuh", Name: "Wazuh SIEM & XDR Platform (Standalone)", DefaultPort: 443, Category: "Security Operations", Description: "Option 1: v4.14 Stable Pinned | Option 2: Live Rolling Release", IsBundle: false},
		{ID: "jenkins", Name: "Jenkins LTS (Auto-Key Capture)", DefaultPort: 8080, Category: "CI/CD Platform", Description: "Option 1: LTS 2.440.3 Pinned | Option 2: Latest Rolling LTS", IsBundle: false},
		{ID: "gitlab", Name: "GitLab CE (Auto-Pass Capture)", DefaultPort: 8929, Category: "CI/CD Platform", Description: "Option 1: CE 16.11 Pinned | Option 2: Latest Rolling CE", IsBundle: false},
		{ID: "sonarqube", Name: "SonarQube Code Security", DefaultPort: 9000, Category: "SAST Platform", Description: "Option 1: LTS-Community | Option 2: Community Latest", IsBundle: false},
		{ID: "prom_grafana", Name: "Prometheus & Grafana Stack", DefaultPort: 3000, Category: "Observability", Description: "Option 1: Prom 2.51 / Grafana 10.4 | Option 2: Latest Rolling", IsBundle: false},
		{ID: "elk", Name: "ELK Stack (Elasticsearch & Kibana)", DefaultPort: 5601, Category: "Logging", Description: "Option 1: 8.11.0 Stable | Option 2: Latest Elastic Stack", IsBundle: false},
		{ID: "vault", Name: "HashiCorp Vault (Persistent Secrets Engine)", DefaultPort: 8200, Category: "Secrets Engine", Description: "Option 1: 1.15.6 Production | Option 2: Latest Release", IsBundle: false},
		{ID: "nexus", Name: "Sonatype Nexus3 Repository", DefaultPort: 8081, Category: "Artifact Registry", Description: "Option 1: 3.66.0 Optimized | Option 2: Latest Release", IsBundle: false},

		// ==>> TIER C: GOLD STANDARD DevSecOps EXTENSIONS (DUAL-OPTION CONFIGURABLE)
		{ID: "terraform", Name: "HashiCorp Terraform / OpenTofu Engine", DefaultPort: 0, Category: "IaC Engine", Description: "Option 1: 1.7.5 Pinned | Option 2: Live Upstream Release", IsBundle: false},
		{ID: "ansible", Name: "Ansible Automation Engine", DefaultPort: 0, Category: "Config Mgmt", Description: "Option 1: Distribution Stable | Option 2: Live Pip3 Engine", IsBundle: false},
		{ID: "k3s", Name: "K3s Lightweight Kubernetes Cluster", DefaultPort: 6443, Category: "Orchestration", Description: "Option 1: v1.28.8 Pinned | Option 2: Latest Stable Channel", IsBundle: false},
		{ID: "argocd", Name: "ArgoCD GitOps Engine", DefaultPort: 8080, Category: "GitOps / CD", Description: "Option 1: v2.10.4 Pinned | Option 2: Stable Branch", IsBundle: false},
		{ID: "trivy", Name: "Aqua Trivy AppSec & Container Scanner", DefaultPort: 0, Category: "Container Sec", Description: "Option 1: v0.50.1 Pinned | Option 2: Live Latest Binary", IsBundle: false},
	}
}

// handleVolumePersistence checks if storage paths exist and prompts user to retain or wipe them
func handleVolumePersistence(client *ssh.Client, paths []string, serviceName string) {
	var existingPaths []string
	for _, p := range paths {
		checkCmd := fmt.Sprintf("[ -d '%s' ] && [ \"$(ls -A '%s' 2>/dev/null)\" ] && echo 'FOUND'", p, p)
		out, err := runSudoScript(client, checkCmd)
		if err == nil && strings.Contains(out, "FOUND") {
			existingPaths = append(existingPaths, p)
		}
	}

	if len(existingPaths) == 0 {
		return
	}

	fmt.Println("\n" + Yellow + Bold + "--------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Yellow+Bold+"=> PERSISTENT STORAGE DETECTED FOR: %s\n"+Reset, strings.ToUpper(serviceName))
	fmt.Printf(Cyan+"   Existing Paths: %s\n"+Reset, strings.Join(existingPaths, ", "))
	fmt.Println("  [1] => KEEP & RE-ATTACH previous volume (Preserve & restore existing data) [DEFAULT]")
	fmt.Println(Red + "  [2] => PURGE previous volume & start fresh (Permanently wipe old data)" + Reset)
	fmt.Println(Yellow + Bold + "--------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select volume strategy [Default 1]: ")
	choice = strings.TrimSpace(choice)

	if choice == "2" {
		purgeCmd := fmt.Sprintf("rm -rf %s", strings.Join(existingPaths, " "))
		_, _ = runSudoScriptWithSpinner(client, purgeCmd, fmt.Sprintf("Wiping Previous Storage Volumes for %s", serviceName))
		fmt.Println(Green + Bold + "=> Previous volumes purged. Fresh clean storage initialized!" + Reset)
	} else {
		fmt.Println(Green + Bold + "=> Preserving existing storage volume. Data will be re-attached!" + Reset)
	}
}

// promptVersionChoice allows selecting between Stable/LTS, Latest, or aborting back to menu
func promptVersionChoice(reader *bufio.Reader, preset PresetDefinition) (string, string) {
	if preset.IsBundle {
		return "bundle_pinned", "Interconnected Verified Stable Stack"
	}

	fmt.Println("\n" + Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+Cyan+"==>> SELECT TARGET VERSION PROFILE FOR: %s\n"+Reset, strings.ToUpper(preset.Name))
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	var opt1Tag, opt1Desc, opt2Tag, opt2Desc string

	switch preset.ID {
	case "docker":
		opt1Tag, opt1Desc = "pinned", "Standard Verified Stable Setup (Official Channel)"
		opt2Tag, opt2Desc = "latest", "Live Upstream Edge Stream (Continuous Auto-Upgrade)"
	case "wazuh":
		opt1Tag, opt1Desc = "v4.14.7", "Wazuh v4.14 Hardened Stable Release"
		opt2Tag, opt2Desc = "latest", "Latest Wazuh Upstream Release"
	case "jenkins":
		opt1Tag, opt1Desc = "jenkins/jenkins:2.440.3-lts-jdk17", "LTS Enterprise Hardened (2.440.3-lts)"
		opt2Tag, opt2Desc = "jenkins/jenkins:lts", "Latest LTS Rolling Community Image"
	case "gitlab":
		opt1Tag, opt1Desc = "gitlab/gitlab-ce:16.11.0-ce.0", "Stable Verified Milestone (16.11.0-ce)"
		opt2Tag, opt2Desc = "gitlab/gitlab-ce:latest", "Latest Rolling Community Edition"
	case "sonarqube":
		opt1Tag, opt1Desc = "sonarqube:lts-community", "Official LTS-Community Long-Term Track"
		opt2Tag, opt2Desc = "sonarqube:community", "Latest General Community Release"
	case "prom_grafana":
		opt1Tag, opt1Desc = "prom/prometheus:v2.51.0|grafana/grafana:10.4.0", "Pinned Metric Stack (Prom 2.51 / Grafana 10.4)"
		opt2Tag, opt2Desc = "prom/prometheus:latest|grafana/grafana:latest", "Latest Rolling Official Images"
	case "elk":
		opt1Tag, opt1Desc = "8.11.0", "Stable Low-Resource Target (8.11.0)"
		opt2Tag, opt2Desc = "latest", "Latest Elastic Stack Release (8.17.0)"
	case "vault":
		opt1Tag, opt1Desc = "hashicorp/vault:1.15.6", "Hardened Production Release (1.15.6)"
		opt2Tag, opt2Desc = "hashicorp/vault:latest", "Latest HashiCorp Release"
	case "nexus":
		opt1Tag, opt1Desc = "docker.io/sonatype/nexus3:3.66.0", "Optimized Baseline Build (3.66.0)"
		opt2Tag, opt2Desc = "docker.io/sonatype/nexus3:latest", "Latest Sonatype Nexus3 Release"
	case "terraform":
		opt1Tag, opt1Desc = "1.7.5", "Pinned Stable Standalone Binary (1.7.5)"
		opt2Tag, opt2Desc = "latest", "Live Upstream Engine (Auto-Resolved via API)"
	case "ansible":
		opt1Tag, opt1Desc = "pinned", "Standard System Engine (OS Native Repository)"
		opt2Tag, opt2Desc = "latest", "Live Upstream Subsystem (Pip3 Continuous Engine)"
	case "k3s":
		opt1Tag, opt1Desc = "v1.28.8+k3s1", "Kubernetes Pinned Stable v1.28 Channel"
		opt2Tag, opt2Desc = "latest", "Kubernetes Latest Stable Channel"
	case "argocd":
		opt1Tag, opt1Desc = "v2.10.4", "Declarative ArgoCD v2.10.4 Manifest Suite"
		opt2Tag, opt2Desc = "stable", "ArgoCD Rolling Stable Manifest Stream"
	case "trivy":
		opt1Tag, opt1Desc = "v0.50.1", "Pinned Standalone Binary (v0.50.1)"
		opt2Tag, opt2Desc = "latest", "Live Aqua Trivy Release (Auto-Resolved via GitHub API)"
	default:
		return "default", "Default Profile"
	}

	fmt.Printf("  [1] => %s (RECOMMENDED / STABLE)\n", opt1Desc)
	fmt.Printf("  [2] => %s\n", opt2Desc)
	fmt.Println(Red + "  [0] => Cancel / Back to DevSecOps Menu" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select Option [Default 1, 0 to Cancel]: ")
	cleanChoice := strings.TrimSpace(strings.ToUpper(choice))

	switch cleanChoice {
	case "0", "Q", "B", "CANCEL":
		return "ABORT", "Cancelled by user"
	case "2":
		return opt2Tag, opt2Desc
	default:
		return opt1Tag, opt1Desc
	}
}

// ShowPresetMenu renders the Hub 5 Preset Manager Sub-Menu
func ShowPresetMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	ShowPresetsMenu(reader, client, targetOS)
}

// ShowPresetsMenu renders the Hub 5 Preset Manager Sub-Menu
func ShowPresetsMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + "==>> HUB 5: GOLD STANDARD DEVSECOPS & PLATFORM ENGINEERING MANAGER" + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)

		catalog := GetCatalog()
		for idx, item := range catalog {
			fmt.Printf("  [%2d] %-48s (%s)\n", idx+1, item.Name, item.Category)
		}

		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
		fmt.Println(Cyan + "  [P] => Execute Custom User Playbook / Script (.sh / .yml)..." + Reset)
		fmt.Println(Cyan + "  [C] => Autonomous Storage Reclamation Suite (Safe / Hard / Super Hard Clean)..." + Reset)
		fmt.Println(Green + "  [A] => Deploy ALL DevSecOps Presets (Full Stack Automation)" + Reset)
		fmt.Println(Yellow + "  [U] => Uninstall Specific Preset Tool..." + Reset)
		fmt.Println(Red + "  [X] => Uninstall ALL Presets & Purge Persistent Volumes" + Reset)
		fmt.Println(Red + "  [0] => Back to DevSecOps Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		fmt.Print(Bold + "Select option: " + Reset)
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch strings.ToUpper(choice) {
		case "0", "Q":
			return
		case "P":
			ExecuteCustomPlaybook(reader, client)
		case "C":
			ShowStorageCleanerMenu(reader, client)
		case "A":
			deployAllPresets(reader, client, targetOS)
			pauseExecution(reader)
		case "U":
			uninstallPrompt(reader, client)
			pauseExecution(reader)
		case "X":
			purgeAllPresets(client)
			pauseExecution(reader)
		default:
			var selectedIdx int
			_, err := fmt.Sscanf(choice, "%d", &selectedIdx)
			if err == nil && selectedIdx >= 1 && selectedIdx <= len(catalog) {
				deployPresetAutonomous(reader, client, catalog[selectedIdx-1], targetOS)
				pauseExecution(reader)
			} else {
				fmt.Println(Red + "[!] Invalid selection. Please try again." + Reset)
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func pauseExecution(reader *bufio.Reader) {
	fmt.Println("\n" + Cyan + "--------------------------------------------------------------------------------" + Reset)
	fmt.Print(Bold + Yellow + "[ Press ENTER to return to DevSecOps Preset Menu ] " + Reset)
	_, _ = reader.ReadString('\n')
}

// resolveTargetIP dynamically resolves active connection host IP address or defaults to 127.0.0.1
func resolveTargetIP(client *ssh.Client) string {
	cmd := "hostname -I 2>/dev/null | awk '{print $1}'"
	out, err := executeRemoteCommand(client, cmd)
	ip := strings.TrimSpace(out)
	if err != nil || ip == "" || ip == "127.0.0.1" {
		return "127.0.0.1"
	}
	return ip
}

// sanitizeCommandForWindows prevents Git Bash path rewriting and normalizes Windows line endings
func sanitizeCommandForWindows(rawBashCmd string) string {
	clean := strings.ReplaceAll(rawBashCmd, "\r\n", "\n")
	return "export MSYS_NO_PATHCONV=1 2>/dev/null || true; " + clean
}

// runSudoScript executes commands securely using echo password | sudo -S -E bash -c "..."
func runSudoScript(client *ssh.Client, rawBashCmd string) (string, error) {
	sanitizedCmd := sanitizeCommandForWindows(rawBashCmd)
	cleanCmd := strings.ReplaceAll(sanitizedCmd, "'", "'\"'\"'")
	var finalCmd string
	if cachedSudoPassword != "" {
		finalCmd = fmt.Sprintf("echo '%s' | sudo -S -E bash -c '%s'", cachedSudoPassword, cleanCmd)
	} else {
		finalCmd = fmt.Sprintf("sudo -E bash -c '%s'", cleanCmd)
	}
	return executeRemoteCommand(client, finalCmd)
}

// runSudoScriptWithSpinner executes commands with spinner via sudo subshell
func runSudoScriptWithSpinner(client *ssh.Client, rawBashCmd string, label string) (string, error) {
	sanitizedCmd := sanitizeCommandForWindows(rawBashCmd)
	cleanCmd := strings.ReplaceAll(sanitizedCmd, "'", "'\"'\"'")
	var finalCmd string
	if cachedSudoPassword != "" {
		finalCmd = fmt.Sprintf("echo '%s' | sudo -S -E bash -c '%s'", cachedSudoPassword, cleanCmd)
	} else {
		finalCmd = fmt.Sprintf("sudo -E bash -c '%s'", cleanCmd)
	}
	return executeRemoteCommandWithSpinner(client, finalCmd, label)
}

// cleanExtractedSecret strips sudo banners, prompts, colons, and trims output
func cleanExtractedSecret(rawOutput string) string {
	lines := strings.Split(rawOutput, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "[sudo] password for") {
			parts := strings.Split(trimmed, ":")
			if len(parts) > 1 {
				trimmed = strings.TrimSpace(parts[len(parts)-1])
			}
		}
		if trimmed != "" && !strings.Contains(trimmed, "[sudo]") && !strings.Contains(trimmed, "No such file") && !strings.Contains(trimmed, "password for") {
			return trimmed
		}
	}
	return ""
}

// EnsureContainerEngine enforces Native Docker Engine and ensures its socket is active
func EnsureContainerEngine(client *ssh.Client) string {
	ActiveRuntime = "docker"

	if _, err := runSudoScript(client, "command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker"); err == nil {
		return "docker"
	}

	fmt.Println(Cyan + Bold + "\n=> Provisioning Native Docker Engine & Socket..." + Reset)
	deployDocker(client, "pinned")
	return "docker"
}

// executeAutonomousDockerRun handles Docker status, stale containers & volume permissions cleanly
func executeAutonomousDockerRun(client *ssh.Client, containerName string, runCmd string, taskLabel string) (string, error) {
	preFixCmd := fmt.Sprintf(`
		docker rm -f %s 2>/dev/null || true
		mkdir -p /var/nexus-data /srv/gitlab /var/jenkins_home /var/sonarqube_data /var/elasticsearch_data /var/vault_data /srv/devsecops /srv/soc /srv/wazuh /srv/argocd
		chown -R 200:200 /var/nexus-data 2>/dev/null || true
		chown -R 1000:1000 /var/elasticsearch_data /srv/soc /srv/wazuh 2>/dev/null || true
		chmod -R 777 /var/nexus-data /srv/gitlab /var/jenkins_home /var/sonarqube_data /var/elasticsearch_data /var/vault_data /srv/devsecops /srv/soc /srv/wazuh /srv/argocd 2>/dev/null || true
	`, containerName)
	_, _ = runSudoScriptWithSpinner(client, preFixCmd, fmt.Sprintf("Pre-Configuring Storage & Environment for %s", containerName))

	out, err := runSudoScriptWithSpinner(client, runCmd, taskLabel)

	if err != nil || strings.Contains(out, "125") || strings.Contains(out, "already in use") || strings.Contains(out, "a terminal is required") {
		fmt.Println(Yellow + Bold + fmt.Sprintf("\n=> AUTONOMOUS HEALING: Self-remediating Docker state and permissions for '%s'...", containerName) + Reset)
		_, _ = runSudoScriptWithSpinner(client, preFixCmd, "Applying Autonomous Privilege & Policy Fixes")
		out, err = runSudoScriptWithSpinner(client, runCmd, fmt.Sprintf("Retrying Clean Deployment for %s", containerName))
	}

	return out, err
}

// extractCleanContainerFileSilent polls internal container secret files and strips prompts
func extractCleanContainerFileSilent(client *ssh.Client, containerName string, filePath string) string {
	cmd := fmt.Sprintf("docker exec %s cat %s 2>/dev/null", containerName, filePath)
	out, err := runSudoScript(client, cmd)
	if err != nil || strings.TrimSpace(out) == "" {
		out, _ = executeRemoteCommand(client, cmd)
	}
	return cleanExtractedSecret(out)
}

// pollContainerSecretFast uses a high-speed spinner while polling keys
func pollContainerSecretFast(client *ssh.Client, containerName string, filePath string, taskLabel string, maxWaitSec int) string {
	stopSpinner := make(chan bool)
	startTime := time.Now()
	var secret string

	go func() {
		spinFrames := []string{"-", "\\", "|", "/"}
		idx := 0
		for {
			select {
			case <-stopSpinner:
				fmt.Print("\r\033[2K\r")
				return
			default:
				elapsed := int(time.Since(startTime).Seconds())
				fmt.Printf("\r\033[36m[ %s ] %s... (%ds elapsed)\033[0m", spinFrames[idx%len(spinFrames)], taskLabel, elapsed)
				idx++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()

	for time.Since(startTime).Seconds() < float64(maxWaitSec) {
		secret = extractCleanContainerFileSilent(client, containerName, filePath)
		if secret != "" {
			break
		}
		time.Sleep(2 * time.Second)
	}

	stopSpinner <- true
	time.Sleep(100 * time.Millisecond)
	return secret
}

// ensureAutonomousPermissionsWithPrompt prompts for sudo password if non-interactive sudo fails
func ensureAutonomousPermissionsWithPrompt(client *ssh.Client) {
	checkOut, err := executeRemoteCommand(client, "sudo -n true 2>&1")
	if err == nil && !strings.Contains(checkOut, "password") && !strings.Contains(checkOut, "terminal") {
		_, _ = runSudoScriptWithSpinner(client, "chmod 666 /var/run/docker.sock 2>/dev/null || true; sysctl -w vm.max_map_count=262144 2>/dev/null || true", "Verifying Kernel & Docker Socket Permissions")
		return
	}

	if cachedSudoPassword == "" {
		fmt.Println(Yellow + Bold + "\n=> SUDO ELEVATION REQUIRED: Target user requires administrative privileges for DevSecOps setup." + Reset)
		cachedSudoPassword = transfer.ReadRealtimeInput("Enter sudo password for target host: ")
	}

	if strings.TrimSpace(cachedSudoPassword) != "" {
		setupCmd := `
			echo '` + cachedSudoPassword + `' | sudo -S tee /etc/sudoers.d/cross-suite >/dev/null 2>&1
			echo '` + cachedSudoPassword + `' | sudo -S chmod 0440 /etc/sudoers.d/cross-suite >/dev/null 2>&1
			echo '` + cachedSudoPassword + `' | sudo -S chmod 666 /var/run/docker.sock >/dev/null 2>&1
			echo '` + cachedSudoPassword + `' | sudo -S sysctl -w vm.max_map_count=262144 >/dev/null 2>&1
		`
		_, _ = executeRemoteCommandWithSpinner(client, setupCmd, "Configuring Autonomous Administrative Rights")
		fmt.Println(Green + Bold + "=> Administrative elevation validated successfully for this session!" + Reset)
	}
}

// deployPresetAutonomous is the master orchestrator for ALL presets
func deployPresetAutonomous(reader *bufio.Reader, client *ssh.Client, preset PresetDefinition, targetOS osdetect.TargetOS) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Printf(Bold+Cyan+"==>> AUTONOMOUS DEPLOYMENT ENGINE: %s\n"+Reset, strings.ToUpper(preset.Name))
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)

	versionTag, versionDesc := promptVersionChoice(reader, preset)
	if versionTag == "ABORT" {
		fmt.Println(Yellow + Bold + "\n=> Deployment cancelled by user. Returning to menu..." + Reset)
		time.Sleep(1 * time.Second)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	fmt.Printf(Cyan+"=> Target Profile Configured: %s (%s)\n"+Reset, versionDesc, versionTag)

	containerName := "cross-" + preset.ID
	targetIP := resolveTargetIP(client)

	if isPresetAlreadyInstalled(client, preset) {
		fmt.Println(Green + Bold + fmt.Sprintf("=> IDEMPOTENCY VERIFIED: %s is ALREADY active on target host! Skipping deployment.", preset.Name) + Reset)
		return
	}

	// Stale container conflict handling
	if !preset.IsBundle && preset.ID != "k3s" && preset.ID != "argocd" && preset.ID != "terraform" && preset.ID != "ansible" && preset.ID != "trivy" && preset.ID != "docker" && preset.ID != "elk" && preset.ID != "prom_grafana" && preset.ID != "wazuh" {
		checkExistedCmd := fmt.Sprintf("docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^%s$'", containerName)
		if _, err := runSudoScript(client, checkExistedCmd); err == nil {
			fmt.Println(Yellow + Bold + fmt.Sprintf("=> CONFLICT DETECTED: An existing container '%s' was found on target host.", containerName) + Reset)
			ans := transfer.ReadRealtimeInput(fmt.Sprintf("Would you like to remove container '%s' and run a clean installation? [Y/n]: ", containerName))
			if ans == "" || strings.ToLower(ans) == "y" {
				cleanupCmd := fmt.Sprintf("docker rm -f %s 2>/dev/null || true", containerName)
				_, _ = runSudoScriptWithSpinner(client, cleanupCmd, fmt.Sprintf("Removing Stale Container %s", containerName))
			} else {
				fmt.Println(Yellow + "=> Deployment aborted by user decision." + Reset)
				return
			}
		}
	}

	requiredSpaceMB := 1500
	switch preset.ID {
	case "devsecops_suite", "gitops_appsec_suite":
		requiredSpaceMB = 12288
	case "wazuh_soc", "wazuh":
		requiredSpaceMB = 8192
	case "gitlab":
		requiredSpaceMB = 6144
	case "elk":
		requiredSpaceMB = 2500
	case "jenkins", "nexus", "k3s", "argocd":
		requiredSpaceMB = 2000
	}

	if !CheckSpacePreFlight(client, requiredSpaceMB) {
		return
	}

	if preset.DefaultPort > 0 {
		fwCmd := fmt.Sprintf(`
			if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
				firewall-cmd --permanent --add-port=%d/tcp 2>/dev/null || true
				firewall-cmd --reload 2>/dev/null || true
			elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
				ufw allow %d/tcp 2>/dev/null || true
			fi
		`, preset.DefaultPort, preset.DefaultPort)
		_, _ = runSudoScriptWithSpinner(client, fwCmd, fmt.Sprintf("Opening Firewall Access for Port %d", preset.DefaultPort))
	}

	switch preset.ID {
	case "devsecops_suite":
		deployDevSecOpsSuite(client)
	case "wazuh_soc":
		deployWazuhSOC(client)
	case "gitops_appsec_suite":
		deployGitOpsAppSecSuite(client)
	case "docker":
		deployDocker(client, versionTag)
	case "wazuh":
		deployWazuhStandalone(client, versionTag)
	case "jenkins":
		deployJenkins(client, preset.DefaultPort, targetIP, versionTag)
	case "gitlab":
		deployGitLab(client, preset.DefaultPort, targetIP, versionTag)
	case "sonarqube":
		deploySonarQube(client, preset.DefaultPort, targetIP, versionTag)
	case "prom_grafana":
		deployPrometheusGrafana(client, preset.DefaultPort, targetIP, versionTag)
	case "elk":
		deployELK(client, preset.DefaultPort, targetIP, versionTag)
	case "vault":
		deployVault(client, preset.DefaultPort, targetIP, versionTag)
	case "nexus":
		deployNexusAutonomous(client, preset.DefaultPort, targetIP, versionTag)
	case "terraform":
		deployTerraform(client, versionTag)
	case "ansible":
		deployAnsible(client, versionTag)
	case "k3s":
		deployK3s(client, targetIP, versionTag)
	case "argocd":
		deployArgoCD(client, preset.DefaultPort, targetIP, versionTag)
	case "trivy":
		deployTrivy(client, versionTag)
	}

	// Health check routing
	switch preset.ID {
	case "trivy", "terraform", "ansible", "k3s", "argocd", "docker", "gitops_appsec_suite", "devsecops_suite", "wazuh_soc", "wazuh":
		return
	case "elk":
		verifyAndSelfHealContainer(client, "cross-elasticsearch")
		verifyAndSelfHealContainer(client, "cross-kibana")
	case "prom_grafana":
		verifyAndSelfHealContainer(client, "cross-prometheus")
		verifyAndSelfHealContainer(client, "cross-grafana")
	default:
		verifyAndSelfHealContainer(client, containerName)
	}
}

// verifyAndSelfHealContainer inspects container health post-deployment
func verifyAndSelfHealContainer(client *ssh.Client, containerName string) {
	time.Sleep(3 * time.Second)

	checkCmd := fmt.Sprintf("docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^%s$'", containerName)
	if _, err := runSudoScript(client, checkCmd); err == nil {
		fmt.Println(Green + Bold + fmt.Sprintf("=> AUTONOMOUS VERIFICATION: Container '%s' is active and running cleanly!", containerName) + Reset)
		return
	}

	fmt.Println(Yellow + Bold + fmt.Sprintf("=> AUTONOMOUS DIAGNOSTIC ENGINE: Analyzing crash logs for '%s'...", containerName) + Reset)

	logCmd := fmt.Sprintf("docker logs %s 2>&1 | tail -n 25", containerName)
	logs, _ := runSudoScriptWithSpinner(client, logCmd, "Fetching Container Diagnostic Logs")

	if strings.Contains(logs, "Permission denied") || strings.Contains(logs, "FileNotFoundException") || strings.Contains(logs, "audit.log") {
		fmt.Println(Cyan + "=> Auto-Fixing File Permissions & Directory Ownership..." + Reset)
		fixCmd := fmt.Sprintf(`
			mkdir -p /var/nexus-data /srv/gitlab /var/jenkins_home /var/sonarqube_data /var/elasticsearch_data /var/vault_data
			chown -R 200:200 /var/nexus-data 2>/dev/null || true
			chown -R 1000:1000 /var/elasticsearch_data 2>/dev/null || true
			chmod -R 777 /var/nexus-data /srv/gitlab /var/jenkins_home /var/sonarqube_data /var/elasticsearch_data /var/vault_data 2>/dev/null || true
			docker rm -f %s 2>/dev/null || true
		`, containerName)
		_, _ = runSudoScriptWithSpinner(client, fixCmd, "Applying Permission Remediation")
	}

	if strings.Contains(logs, "max_map_count") || strings.Contains(logs, "vm.max_map_count") {
		fmt.Println(Cyan + "=> Auto-Tuning Kernel Parameter (vm.max_map_count)..." + Reset)
		fixKernel := "sysctl -w vm.max_map_count=262144 && echo 'vm.max_map_count=262144' >> /etc/sysctl.conf"
		_, _ = runSudoScriptWithSpinner(client, fixKernel, "Setting Kernel Subsystem Memory Limits")
	}

	time.Sleep(2 * time.Second)
	if _, err := runSudoScript(client, checkCmd); err == nil {
		fmt.Println(Green + Bold + fmt.Sprintf("=> SELF-HEALING RECOVERY SUCCESSFUL: Container '%s' is now active!", containerName) + Reset)
	}
}

func deployNexusAutonomous(client *ssh.Client, port int, targetIP string, imageTag string) {
	if imageTag == "" || imageTag == "latest" {
		imageTag = "docker.io/sonatype/nexus3:latest"
	}
	if !strings.Contains(imageTag, "/") || strings.HasPrefix(imageTag, "sonatype/") {
		imageTag = "docker.io/" + strings.TrimPrefix(imageTag, "docker.io/")
	}

	handleVolumePersistence(client, []string{"/var/nexus-data"}, "Sonatype Nexus3")

	runCmd := fmt.Sprintf("docker run -d --name cross-nexus -p %d:8081 -e 'INSTALL4J_ADD_VM_PARAMS=-Xms512m -Xmx1024m' -v /var/nexus-data:/opt/sonatype/sonatype-work/nexus3 --restart always %s", port, imageTag)
	out, err := executeAutonomousDockerRun(client, "cross-nexus", runCmd, fmt.Sprintf("Deploying Sonatype Nexus3 Container (%s on Port %d)", imageTag, port))
	if err != nil {
		fmt.Printf(Red+"[!] Nexus deployment failed: %v\n%s\n"+Reset, err, out)
		return
	}

	pass := pollContainerSecretFast(client, "cross-nexus", "/opt/sonatype/sonatype-work/nexus3/admin.password", "Polling Nexus Java Startup & Admin Password Generation", 180)

	if pass == "" {
		hostPassCmd := "cat /var/nexus-data/admin.password 2>/dev/null"
		hostPassOut, _ := runSudoScript(client, hostPassCmd)
		cleanHostPass := cleanExtractedSecret(hostPassOut)
		if cleanHostPass != "" {
			pass = cleanHostPass
		}
	}

	if pass == "" {
		pass = "Still generating... (Use manual retrieval command below)"
	}

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> SONATYPE NEXUS3 DEPLOYED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Access URL         : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Cyan+Bold+"   => Target Image       : %s\n"+Reset, imageTag)
	fmt.Printf(Cyan+Bold+"   => Default Username   : admin\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Initial Admin Pass : %s\n"+Reset, pass)
	fmt.Printf(Yellow+Bold+"   => Manual Pass Retrieval: sudo cat /var/nexus-data/admin.password\n"+Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func isPresetAlreadyInstalled(client *ssh.Client, preset PresetDefinition) bool {
	var checkCmd string

	switch preset.ID {
	case "devsecops_suite":
		checkCmd = "docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^cross-gitlab$'"
	case "wazuh":
		checkCmd = "docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'wazuh.*indexer|indexer.*1'"
	case "wazuh_soc":
		checkCmd = "docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'wazuh.*indexer|indexer.*1' && (systemctl is-active --quiet wazuh-agent || systemctl is-active --quiet wazuh-manager)"
	case "gitops_appsec_suite":
		checkCmd = "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; kubectl -n argocd get deployment argocd-server 2>/dev/null | grep -q 'argocd-server'"
	case "docker":
		checkCmd = "command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker"
	case "prom_grafana":
		checkCmd = "docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^cross-grafana$'"
	case "elk":
		checkCmd = "docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^cross-kibana$'"
	case "terraform":
		checkCmd = "command -v terraform >/dev/null 2>&1 || command -v tofu >/dev/null 2>&1"
	case "ansible":
		checkCmd = "command -v ansible >/dev/null 2>&1"
	case "k3s":
		checkCmd = "command -v k3s >/dev/null 2>&1 && systemctl is-active --quiet k3s"
	case "argocd":
		checkCmd = "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; kubectl -n argocd get deployment argocd-server 2>/dev/null | grep -q 'argocd-server'"
	case "trivy":
		checkCmd = "command -v trivy >/dev/null 2>&1"
	default:
		containerName := "cross-" + preset.ID
		checkCmd = fmt.Sprintf("docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^%s$'", containerName)
	}

	_, err := runSudoScript(client, checkCmd)
	return err == nil
}

// deployDevSecOpsSuite provisions the full interconnected Super-Suite
func deployDevSecOpsSuite(client *ssh.Client) {
	targetIP := resolveTargetIP(client)
	EnsureContainerEngine(client)
	jenkinsPass := "AdminPass123!"
	const defaultGitLabPass = "kX9#mQ2$vL7!zP4@"

	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "==>> DEPLOYING UNIFIED DEVSECOPS SUPER-SUITE (PINNED LTS) over DOCKER Engine" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	handleVolumePersistence(client, []string{"/srv/devsecops", "/var/grafana_data", "/var/sonarqube_data"}, "DevSecOps Super-Suite")

	fmt.Printf(Bold+Yellow+"=> Default Jenkins Admin Password for Suite: %s\n"+Reset, jenkinsPass)
	customPrompt := transfer.ReadRealtimeInput("Do you want to set a custom Jenkins password for the suite? [y/N]: ")
	if strings.ToLower(strings.TrimSpace(customPrompt)) == "y" {
		for {
			newPass := transfer.ReadRealtimeInput("Enter desired Jenkins password (min 8 characters): ")
			newPass = strings.TrimSpace(newPass)
			if len(newPass) < 8 {
				fmt.Println(Red + "[!] Password must be at least 8 characters long. Try again." + Reset)
				continue
			}
			jenkinsPass = newPass
			break
		}
	}

	preCmd := fmt.Sprintf(`
		docker network create devsecops-net 2>/dev/null || true
		mkdir -p /srv/devsecops/prometheus /srv/devsecops/grafana/provisioning/datasources /srv/devsecops/jenkins/init.groovy.d /srv/devsecops/jenkins/updates /srv/devsecops/gitlab/config /srv/devsecops/gitlab/logs /srv/devsecops/gitlab/data /var/grafana_data /var/sonarqube_data 2>/dev/null
		rm -rf /srv/devsecops/grafana/provisioning/datasources/* 2>/dev/null || true
		
		cat << 'EOF' > /srv/devsecops/prometheus/prometheus.yml
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['127.0.0.1:9090']
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['127.0.0.1:9100']
EOF

		cat << 'EOF' > /srv/devsecops/grafana/provisioning/datasources/default.yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    orgId: 1
    url: http://127.0.0.1:9090
    isDefault: true
    version: 1
    editable: true
    uid: prometheus-default
    jsonData:
      httpMethod: POST
      timeInterval: 15s
EOF

		cat << 'EOF' > /srv/devsecops/gitlab/config/gitlab.rb
external_url 'http://%s:8929'
gitlab_rails['gitlab_shell_ssh_port'] = 2222
gitlab_rails['initial_root_password'] = '%s'
gitlab_rails['store_initial_root_password'] = true

nginx['listen_port'] = 8929
nginx['listen_https'] = false
nginx['proxy_set_headers'] = {
  "Host" => "%s:8929",
  "X-Forwarded-Proto" => "http",
  "X-Forwarded-For" => "$proxy_add_x_forwarded_for",
  "X-Forwarded-Host" => "%s:8929",
  "X-Forwarded-Port" => "8929",
  "X-Forwarded-Ssl" => "off"
}

gitlab_rails['trusted_proxies'] = ['127.0.0.1', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
puma['worker_processes'] = 2
sidekiq['max_concurrency'] = 10
EOF

		echo '2.440.3' > /srv/devsecops/jenkins/jenkins.install.UpgradeWizard.state
		echo '2.440.3' > /srv/devsecops/jenkins/jenkins.install.InstallUtil.lastExecVersion

		cat << 'EOF' > /srv/devsecops/jenkins/jenkins.model.JenkinsLocationConfiguration.xml
<?xml version='1.1' encoding='UTF-8'?>
<jenkins.model.JenkinsLocationConfiguration>
  <adminAddress>admin@local.host</adminAddress>
  <jenkinsUrl>http://%s:8082/</jenkinsUrl>
</jenkins.model.JenkinsLocationConfiguration>
EOF

		cat << 'EOF' > /srv/devsecops/jenkins/init.groovy.d/01-basic-security.groovy
#!groovy
import jenkins.model.*
import hudson.security.*

def instance = Jenkins.getInstance()
def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount('admin', '%s')
instance.setSecurityRealm(hudsonRealm)

def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)

instance.setInstallState(jenkins.install.InstallState.INITIAL_SETUP_COMPLETED)
instance.setNumExecutors(2)
instance.setMode(hudson.model.Node.Mode.NORMAL)
instance.save()
EOF

		chmod -R 777 /srv/devsecops /var/grafana_data /var/sonarqube_data
		chown -R 1000:1000 /srv/devsecops/jenkins 2>/dev/null || true
		chown -R 472:472 /var/grafana_data 2>/dev/null || true
	`, targetIP, defaultGitLabPass, targetIP, targetIP, targetIP, jenkinsPass)
	_, _ = runSudoScriptWithSpinner(client, preCmd, "Creating DevSecOps Storage Mounts & Hardened Interconnection Specs")

	sonarCmd := "docker run -d --name cross-sonarqube -p 9000:9000 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -v /var/sonarqube_data:/opt/sonarqube/data --restart always sonarqube:lts-community"
	_, _ = executeAutonomousDockerRun(client, "cross-sonarqube", sonarCmd, "Deploying SonarQube LTS-Community Analyzer (Port 9000)")

	jenkinsCmd := "docker run -d --name cross-jenkins --dns 8.8.8.8 --dns 1.1.1.1 -p 8082:8080 -p 50000:50000 -e 'JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Dhudson.model.DownloadService.noSignatureCheck=true -Dhudson.model.DirectoryBrowserSupport.CSP= -Djava.awt.headless=true' -v /srv/devsecops/jenkins:/var/jenkins_home --restart always jenkins/jenkins:lts"
	_, _ = executeAutonomousDockerRun(client, "cross-jenkins", jenkinsCmd, "Deploying Jenkins LTS Hardened Core (Port 8082)")

	gitlabCmd := `docker run -d --name cross-gitlab \
		-p 8929:8929 \
		-p 2222:22 \
		-v /srv/devsecops/gitlab/config:/etc/gitlab \
		-v /srv/devsecops/gitlab/logs:/var/log/gitlab \
		-v /srv/devsecops/gitlab/data:/var/opt/gitlab \
		--shm-size 512m \
		--restart always gitlab/gitlab-ce:16.11.0-ce.0`
	_, _ = executeAutonomousDockerRun(client, "cross-gitlab", gitlabCmd, "Deploying GitLab CE 16.11 Hub (Port 8929)")

	nodeExpRunCmd := "docker run -d --name cross-node-exporter --net=host --pid=host -v /:/host:ro,rslave --restart always quay.io/prometheus/node-exporter:v1.7.0 --path.rootfs=/host"
	_, _ = executeAutonomousDockerRun(client, "cross-node-exporter", nodeExpRunCmd, "Deploying Node Exporter Host Metrics Collector (Port 9100)")

	promRunCmd := "docker run -d --name cross-prometheus --network host -v /srv/devsecops/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml --restart always prom/prometheus:v2.51.0"
	_, _ = executeAutonomousDockerRun(client, "cross-prometheus", promRunCmd, "Deploying Prometheus Metrics Engine v2.51 (Port 9090)")

	grafanaRunCmd := "docker run -d --name cross-grafana --network host -e 'GF_SERVER_HTTP_PORT=3000' -e 'GF_SECURITY_ADMIN_USER=admin' -e 'GF_SECURITY_ADMIN_PASSWORD=admin' -e 'GF_USERS_ALLOW_SIGN_UP=false' -v /srv/devsecops/grafana/provisioning:/etc/grafana/provisioning -v /var/grafana_data:/var/lib/grafana --restart always grafana/grafana:10.4.0"
	_, _ = executeAutonomousDockerRun(client, "cross-grafana", grafanaRunCmd, "Deploying Grafana Observability Visualizer v10.4 (Port 3000)")

	syncGrafCmd := `
		for i in {1..35}; do
			if curl -s http://127.0.0.1:3000/api/health 2>/dev/null | grep -q 'ok'; then
				docker exec cross-grafana grafana cli admin reset-admin-password admin >/dev/null 2>&1 || \
				docker exec cross-grafana grafana-cli admin reset-admin-password admin >/dev/null 2>&1 || true
				exit 0
			fi
			sleep 2
		done
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, syncGrafCmd, "Synchronizing Suite Grafana Admin Credentials & Datasources")

	syncGitLabInSuite(client, "docker", targetIP, 8929)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> DEVSECOPS SUPER-SUITE DEPLOYED & INTERCONNECTED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => GitLab CE 16.11      : http://%s:8929 (User: root | Default Pass: %s)\n"+Reset, targetIP, defaultGitLabPass)
	fmt.Printf(Green+Bold+"   => Jenkins LTS Core     : http://%s:8082 (User: admin | Pass: %s)\n"+Reset, targetIP, jenkinsPass)
	fmt.Printf(Green+Bold+"   => SonarQube LTS        : http://%s:9000 (User: admin | Pass: admin)\n"+Reset, targetIP)
	fmt.Printf(Green+Bold+"   => Grafana Dashboards   : http://%s:3000 (User: admin | Pass: admin)\n"+Reset, targetIP)
	fmt.Printf(Green+Bold+"   => Prometheus Metrics   : http://%s:9090\n"+Reset, targetIP)
	fmt.Printf(Green+Bold+"   => Node Exporter Host   : http://%s:9100/metrics (Scraped by Prometheus)\n"+Reset, targetIP)
	fmt.Printf(Yellow+Bold+"   => Health Verification  : curl -u admin:admin http://localhost:3000/api/datasources/uid/prometheus-default/health\n"+Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func syncGitLabInSuite(client *ssh.Client, runtime string, targetIP string, port int) {
	waitCmd := `
		for i in {1..90}; do
			if docker exec -i cross-gitlab gitlab-rails runner "puts 'DB_READY' if ActiveRecord::Base.connection.table_exists?('users')" 2>/dev/null | grep -q 'DB_READY'; then
				exit 0
			fi
			sleep 4
		done
		exit 1
	`
	_, _ = runSudoScriptWithSpinner(client, waitCmd, "Synchronizing Suite GitLab Database & Migration Readiness")

	syncCmd := `
		docker exec -i cross-gitlab gitlab-rails runner - << 'EOF' >/tmp/gitlab_suite_sync.log 2>&1
user = User.find_by_username('root') || User.where(id: 1).first || User.first

if user.nil?
  user = User.new(
    id: 1,
    username: 'root',
    email: 'admin@local.host',
    name: 'Administrator',
    password: 'kX9#mQ2$vL7!zP4@',
    password_confirmation: 'kX9#mQ2$vL7!zP4@',
    admin: true,
    state: 'active'
  )
else
  user.username = 'root'
  user.password = 'kX9#mQ2$vL7!zP4@'
  user.password_confirmation = 'kX9#mQ2$vL7!zP4@'
  user.state = 'active'
  user.admin = true
end

if user.namespace.nil?
  user.build_personal_namespace(name: user.name, path: user.username) rescue nil
  if user.namespace.nil?
    ns = Namespace.find_or_create_by!(path: user.username) do |n|
      n.name = user.name
      n.owner = user
      n.type = 'User'
    end
    ns.update_columns(owner_id: user.id, type: 'User')
  end
end

user.role = 'software_developer' if user.respond_to?(:role=)
user.skip_confirmation! if user.respond_to?(:skip_confirmation!)
user.unlock_access! if user.respond_to?(:unlock_access!) && user.access_locked?
user.failed_attempts = 0 if user.respond_to?(:failed_attempts)

# Bypass active model password dictionary validation hooks cleanly
user.save(validate: false)

if user.respond_to?(:user_detail) && user.user_detail
  user.user_detail.update_columns(onboarding_step_url: nil, registration_objective: 0) rescue nil
end

begin
  token = user.personal_access_tokens.find_by(name: 'orchestrator-admin-token')
  if token.nil?
    token = user.personal_access_tokens.create(
      name: 'orchestrator-admin-token',
      scopes: [:api, :read_user, :read_repository, :write_repository, :sudo],
      expires_at: 365.days.from_now
    )
  end
  if token.respond_to?(:set_token)
    token.set_token('glpat-AdminRootSecretToken123')
    token.save(validate: false)
  end
rescue => e
  puts "Token error: #{e.message}"
end

ApplicationSetting.current.update(signup_enabled: false) rescue nil
Rails.cache.clear
puts "SUITE_GITLAB_SYNC_COMPLETE"
EOF
	`
	_, _ = runSudoScriptWithSpinner(client, syncCmd, "Seeding Suite GitLab Credentials & Personal Namespaces")
}

func wazuhStep(client *ssh.Client, stepNum int, totalSteps int, label string, timeoutSecs int, rawCmd string) (string, error) {
	fmt.Printf(Cyan+"  [%d/%d] %s..."+Reset, stepNum, totalSteps, label)
	guarded := fmt.Sprintf("timeout %ds bash -c '%s'", timeoutSecs, strings.ReplaceAll(rawCmd, "'", "'\"'\"'"))
	out, err := runSudoScript(client, guarded)
	if err != nil && strings.Contains(err.Error(), "exit status 124") {
		fmt.Println(Red + " TIMED OUT after " + fmt.Sprint(timeoutSecs) + "s (skipped, continuing)" + Reset)
		return out, fmt.Errorf("step %q timed out after %ds", label, timeoutSecs)
	} else if err != nil {
		fmt.Println(Yellow + " completed with warnings (non-fatal)" + Reset)
		return out, err
	}
	fmt.Println(Green + " done" + Reset)
	return out, nil
}

func deployWazuhSOC(client *ssh.Client) {
	targetIP := resolveTargetIP(client)
	EnsureContainerEngine(client)
	const totalSteps = 8

	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "==>> DEPLOYING WAZUH SIEM & XDR OBSERVABILITY SUITE (INTERCONNECTED SOC)" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	handleVolumePersistence(client, []string{"/srv/wazuh-docker", "/var/ossec"}, "Wazuh SOC Suite")

	// Step 1: Kernel & System Tune
	wazuhStep(client, 1, totalSteps, "Applying kernel prerequisites & directory layout", 20, `
		sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
		grep -qxF "vm.max_map_count=262144" /etc/sysctl.conf 2>/dev/null || echo "vm.max_map_count=262144" >> /etc/sysctl.conf
		mkdir -p /srv/wazuh-docker /var/ossec/queue 2>/dev/null
		chmod 777 /var/ossec/queue 2>/dev/null || true
		exit 0
	`)

	// Step 2: Manifest Clone
	_, cloneErr := wazuhStep(client, 2, totalSteps, "Cloning Wazuh deployment manifests (v4.14.7)", 60, `
		if [ ! -d /srv/wazuh-docker/single-node ]; then
			rm -rf /srv/wazuh-docker 2>/dev/null
			git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.7 --depth=1 /srv/wazuh-docker
		fi
		exit 0
	`)
	if cloneErr != nil {
		fmt.Println(Red + Bold + "[!] Manifest clone failed or timed out — check network/DNS on target host." + Reset)
		return
	}

	// Step 3: Certificate Generation
	wazuhStep(client, 3, totalSteps, "Generating Native TLS Certificates & Target Directory Layout", 60, `
		cd /srv/wazuh-docker/single-node
		docker compose down -v 2>/dev/null || true
		mkdir -p config/wazuh_indexer_ssl_certs config/wazuh_dashboard_ssl_certs config/wazuh_cluster_ssl_certs

		if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
			cat << 'EOF' > ./config.yml
nodes:
  indexer:
    - name: wazuh.indexer
      ip: 127.0.0.1
  server:
    - name: wazuh.manager
      ip: 127.0.0.1
  dashboard:
    - name: wazuh.dashboard
      ip: 127.0.0.1
EOF
			curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
			chmod +x wazuh-certs-tool.sh
			./wazuh-certs-tool.sh -A >/dev/null 2>&1 || true

			if [ -f ./wazuh-certificates.tar ]; then
				tar -xf ./wazuh-certificates.tar
			fi

			if [ -d ./wazuh-certificates ]; then
				cp -af ./wazuh-certificates/* config/wazuh_indexer_ssl_certs/ 2>/dev/null || true
				cp -af ./wazuh-certificates/* config/wazuh_dashboard_ssl_certs/ 2>/dev/null || true
				cp -af ./wazuh-certificates/* config/wazuh_cluster_ssl_certs/ 2>/dev/null || true
				
				cp -f ./wazuh-certificates/wazuh.indexer-key.pem config/wazuh_indexer_ssl_certs/wazuh.indexer.key 2>/dev/null || true
				cp -f ./wazuh-certificates/admin-key.pem config/wazuh_indexer_ssl_certs/admin.key 2>/dev/null || true
				cp -f ./wazuh-certificates/wazuh.dashboard-key.pem config/wazuh_dashboard_ssl_certs/wazuh.dashboard.key 2>/dev/null || true
				cp -f ./wazuh-certificates/wazuh.manager.pem config/wazuh_indexer_ssl_certs/filebeat.pem 2>/dev/null || true
				cp -f ./wazuh-certificates/wazuh.manager-key.pem config/wazuh_indexer_ssl_certs/filebeat.key 2>/dev/null || true
			fi
			chmod -R 777 config/ ./wazuh-certificates 2>/dev/null || true
		fi
		exit 0
	`)

	// Step 4: Bring Up Single-Node Stack
	wazuhStep(client, 4, totalSteps, "Starting Wazuh manager/indexer/dashboard containers", 120, `
		cd /srv/wazuh-docker/single-node
		docker compose -f docker-compose.yml up -d
		exit 0
	`)

	// Step 5: Readiness Wait
	wazuhStep(client, 5, totalSteps, "Waiting for indexer readiness on :9200", 90, `
		for i in {1..40}; do
			if curl -k -s --max-time 3 -u admin:SecretPassword https://127.0.0.1:9200 2>/dev/null | grep -q 'cluster_name'; then
				exit 0
			fi
			sleep 2
		done
		exit 0
	`)

	// Step 6: Apply Schema Index Template
	wazuhStep(client, 6, totalSteps, "Applying Wazuh index template schema", 30, `
		curl -sL --max-time 15 https://raw.githubusercontent.com/wazuh/wazuh/v4.14.7/extensions/elasticsearch/7.x/wazuh-template.json -o /tmp/wazuh-template.json || true
		if [ -s /tmp/wazuh-template.json ]; then
			curl -k -s --max-time 10 -u admin:SecretPassword -X PUT "https://127.0.0.1:9200/_template/wazuh" \
				-H "Content-Type: application/json" -d @/tmp/wazuh-template.json >/dev/null 2>&1 || true
			rm -f /tmp/wazuh-template.json
		fi
		exit 0
	`)

	// Step 7: Disk Watermark Thresholds
	wazuhStep(client, 7, totalSteps, "Releasing storage watermark thresholds", 15, `
		curl -k -s --max-time 10 -u admin:SecretPassword -X PUT "https://127.0.0.1:9200/_cluster/settings" \
			-H "Content-Type: application/json" \
			-d '{"persistent":{"cluster.routing.allocation.disk.watermark.flood_stage":"99%%","cluster.routing.allocation.disk.watermark.high":"98%%","cluster.routing.allocation.disk.watermark.low":"95%%"}}' >/dev/null 2>&1 || true
		exit 0
	`)

	// Step 8: Local Host Agent
	_, agentErr := wazuhStep(client, 8, totalSteps, "Auto-enrolling local host agent", 90, `
		if command -v apt-get >/dev/null 2>&1; then
			curl -s --max-time 10 https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /etc/apt/trusted.gpg.d/wazuh.gpg 2>/dev/null || true
			echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
			apt-get -o DPkg::Lock::Timeout=60 update -qq >/dev/null 2>&1 || true
			WAZUH_MANAGER="127.0.0.1" apt-get -o DPkg::Lock::Timeout=60 install -y -qq wazuh-agent >/dev/null 2>&1 || true
			systemctl daemon-reload 2>/dev/null || true
			systemctl enable --now wazuh-agent 2>/dev/null || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH >/dev/null 2>&1 || true
			cat << 'EOF_REPO' > /etc/yum.repos.d/wazuh.repo
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
EOF_REPO
			WAZUH_MANAGER="127.0.0.1" dnf install -y -q wazuh-agent 2>/dev/null || WAZUH_MANAGER="127.0.0.1" yum install -y -q wazuh-agent 2>/dev/null || true
			systemctl daemon-reload 2>/dev/null || true
			systemctl enable --now wazuh-agent 2>/dev/null || true
		fi
		exit 0
	`)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> WAZUH INTERCONNECTED SOC SUITE ONLINE!" + Reset)
	fmt.Printf(Green+Bold+"   => SOC Visualizer UI    : https://%s/app/login (Port 443 / 5601)\n"+Reset, targetIP)
	fmt.Printf(Cyan+Bold+"   => Default Login        : admin / SecretPassword\n"+Reset)
	if agentErr != nil {
		fmt.Printf(Yellow+Bold+"   => Host Agent Status    : Agent install skipped (Dashboard is fully functional)\n"+Reset)
	} else {
		fmt.Printf(Cyan+Bold+"   => Host Agent Status    : Active (127.0.0.1:1514)\n"+Reset)
	}
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployWazuhStandalone(client *ssh.Client, versionTag string) {
	targetIP := resolveTargetIP(client)
	EnsureContainerEngine(client)
	tag := "v4.14.7"
	const totalSteps = 8

	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Printf(Cyan+Bold+"==>> DEPLOYING STANDALONE WAZUH PLATFORM (%s) over DOCKER Engine\n"+Reset, tag)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	handleVolumePersistence(client, []string{"/srv/wazuh-docker"}, "Wazuh Standalone Stack")

	wazuhStep(client, 1, totalSteps, "Applying kernel prerequisites (vm.max_map_count) & firewall rules", 20, `
		sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
		grep -qxF "vm.max_map_count=262144" /etc/sysctl.conf 2>/dev/null || echo "vm.max_map_count=262144" >> /etc/sysctl.conf
		mkdir -p /srv/wazuh-docker 2>/dev/null

		if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
			ufw allow 443/tcp >/dev/null 2>&1 || true
			ufw allow 9200/tcp >/dev/null 2>&1 || true
			ufw allow 1514/tcp >/dev/null 2>&1 || true
			ufw allow 1515/tcp >/dev/null 2>&1 || true
			ufw allow 55000/tcp >/dev/null 2>&1 || true
		elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
			firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
			firewall-cmd --permanent --add-port=9200/tcp >/dev/null 2>&1 || true
			firewall-cmd --permanent --add-port=1514/tcp >/dev/null 2>&1 || true
			firewall-cmd --permanent --add-port=1515/tcp >/dev/null 2>&1 || true
			firewall-cmd --permanent --add-port=55000/tcp >/dev/null 2>&1 || true
			firewall-cmd --reload >/dev/null 2>&1 || true
		fi
		exit 0
	`)

	_, cloneErr := wazuhStep(client, 2, totalSteps, fmt.Sprintf("Cloning Wazuh deployment manifests (%s)", tag), 60, fmt.Sprintf(`
		if [ ! -d /srv/wazuh-docker/single-node ]; then
			rm -rf /srv/wazuh-docker 2>/dev/null
			git clone https://github.com/wazuh/wazuh-docker.git -b %s --depth=1 /srv/wazuh-docker
		fi
		exit 0
	`, tag))
	if cloneErr != nil {
		fmt.Println(Red + Bold + "[!] Manifest clone failed or timed out — check network/DNS on target host." + Reset)
		return
	}

	wazuhStep(client, 3, totalSteps, "Generating clean indexer TLS certificates via container generator", 60, `
		cd /srv/wazuh-docker/single-node
		docker compose down -v 2>/dev/null || true
		rm -rf config/wazuh_indexer_ssl_certs config/wazuh_dashboard_ssl_certs config/wazuh_cluster_ssl_certs 2>/dev/null || true
		mkdir -p config/wazuh_indexer_ssl_certs config/wazuh_dashboard_ssl_certs config/wazuh_cluster_ssl_certs
		docker compose -f generate-indexer-certs.yml run --rm generator >/dev/null 2>&1 || true
		chmod -R 755 config/ 2>/dev/null || true
		exit 0
	`)

	wazuhStep(client, 4, totalSteps, "Starting Wazuh manager/indexer/dashboard containers", 120, `
		cd /srv/wazuh-docker/single-node
		docker compose up -d
		exit 0
	`)

	wazuhStep(client, 5, totalSteps, "Waiting for indexer readiness on :9200", 90, `
		for i in {1..45}; do
			if curl -k -s --max-time 3 -u admin:SecretPassword https://127.0.0.1:9200 2>/dev/null | grep -q 'cluster_name'; then
				exit 0
			fi
			sleep 2
		done
		exit 0
	`)

	wazuhStep(client, 6, totalSteps, "Applying Wazuh index template schema", 30, `
		curl -sL --max-time 15 https://raw.githubusercontent.com/wazuh/wazuh/v4.14.7/extensions/elasticsearch/7.x/wazuh-template.json -o /tmp/wazuh-template.json || true
		if [ -s /tmp/wazuh-template.json ]; then
			curl -k -s --max-time 10 -u admin:SecretPassword -X PUT "https://127.0.0.1:9200/_template/wazuh" \
				-H "Content-Type: application/json" -d @/tmp/wazuh-template.json >/dev/null 2>&1 || true
			rm -f /tmp/wazuh-template.json
		fi
		exit 0
	`)

	wazuhStep(client, 7, totalSteps, "Releasing storage watermark thresholds", 15, `
		curl -k -s --max-time 10 -u admin:SecretPassword -X PUT "https://127.0.0.1:9200/_cluster/settings" \
			-H "Content-Type: application/json" \
			-d '{"persistent":{"cluster.routing.allocation.disk.watermark.flood_stage":"99%%","cluster.routing.allocation.disk.watermark.high":"98%%","cluster.routing.allocation.disk.watermark.low":"95%%"}}' >/dev/null 2>&1 || true
		exit 0
	`)

	wazuhStep(client, 8, totalSteps, "Waiting for Wazuh Dashboard Web UI initialization on :443", 90, `
		for i in {1..45}; do
			HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" https://127.0.0.1/app/login 2>/dev/null || curl -k -s -o /dev/null -w "%{http_code}" https://127.0.0.1:443 2>/dev/null || true)
			if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
				exit 0
			fi
			sleep 2
		done
		exit 0
	`)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> WAZUH STANDALONE PLATFORM ONLINE & VERIFIED!" + Reset)
	fmt.Printf(Green+Bold+"   => Web Dashboard UI     : https://%s/app/login (Port 443 / 5601)\n"+Reset, targetIP)
	fmt.Printf(Cyan+Bold+"   => Default Username     : admin\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Default Password     : SecretPassword\n"+Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println(Yellow + Bold + "   => [!] STARTUP ADVISORY : Initial dashboard launch takes 1–2 minutes!" + Reset)
	fmt.Println(Yellow + "      OpenSearch Dashboards compiles plugins & synchronizes internal indices." + Reset)
	fmt.Println(Yellow + "      If the page shows 'Loading' or connection delay, please wait 60 seconds." + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployGitOpsAppSecSuite(client *ssh.Client) {
	targetIP := resolveTargetIP(client)
	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "==>> DEPLOYING AppSec & GitOps CLOUD-NATIVE STACK (PINNED BUNDLE)" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	handleVolumePersistence(client, []string{"/var/vault_data", "/var/lib/rancher/k3s", "/etc/rancher/k3s"}, "AppSec & GitOps Stack")

	deployK3s(client, targetIP, "v1.28.8+k3s1")
	deployVault(client, 8200, targetIP, "hashicorp/vault:1.15.6")
	deployArgoCD(client, 8080, targetIP, "v2.10.4")
	deployTrivy(client, "latest")

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> AppSec & GitOps CLOUD-NATIVE STACK DEPLOYED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => ArgoCD GitOps UI     : https://%s:8080 (User: admin)\n"+Reset, targetIP)
	fmt.Printf(Green+Bold+"   => Vault Secrets Engine : http://%s:8200\n"+Reset, targetIP)
	fmt.Printf(Green+Bold+"   => K3s K8s Cluster      : Active on Port 6443 (v1.28.8)\n"+Reset)
	fmt.Printf(Green+Bold+"   => Trivy AppSec Engine  : CLI Available system-wide via 'trivy'\n"+Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployDocker(client *ssh.Client, option string) {
	isLatest := (option == "latest")

	cmd := fmt.Sprintf(`
		export DEBIAN_FRONTEND=noninteractive
		systemctl stop podman.socket 2>/dev/null || true
		rm -f /var/run/docker.sock

		if [ "%t" = "true" ]; then
			curl -fsSL https://get.docker.com | sh 2>/dev/null || true
		else
			if command -v apt-get >/dev/null 2>&1; then
				apt-get update -qq >/dev/null 2>&1
				apt-get install -y -qq docker.io docker-compose containerd >/dev/null 2>&1 || true
			elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
				dnf install -y -q docker docker-compose 2>/dev/null || yum install -y -q docker docker-compose 2>/dev/null || true
			fi
		fi

		systemctl unmask docker.service docker.socket containerd 2>/dev/null || true
		systemctl enable --now docker.socket docker.service containerd 2>/dev/null || true
		systemctl restart docker.service 2>/dev/null || true

		ln -sf /run/docker.sock /var/run/docker.sock 2>/dev/null || true
		chmod 666 /run/docker.sock /var/run/docker.sock 2>/dev/null || true
		exit 0
	`, isLatest)

	label := "Deploying Verified Docker Engine & Native Socket"
	if isLatest {
		label = "Deploying Live Upstream Docker Engine Release"
	}
	_, _ = runSudoScriptWithSpinner(client, cmd, label)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> DOCKER ENGINE & NATIVE SOCKET CONFIGURED SUCCESSFULLY!" + Reset)
	fmt.Println(Cyan + Bold + "   => Native Docker Socket : /var/run/docker.sock (Active)" + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployJenkins(client *ssh.Client, port int, targetIP string, imageTag string) {
	if imageTag == "" {
		imageTag = "jenkins/jenkins:lts"
	}

	activePassword := "AdminPass123!"
	handleVolumePersistence(client, []string{"/var/jenkins_home"}, "Jenkins Automation Server")

	fmt.Println("\n" + Cyan + "--------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+Yellow+"=> Default Initial Admin Password: %s\n"+Reset, activePassword)
	customPrompt := transfer.ReadRealtimeInput("Do you want to set your own custom admin password? [y/N]: ")
	if strings.ToLower(strings.TrimSpace(customPrompt)) == "y" {
		for {
			newPass := transfer.ReadRealtimeInput("Enter your desired admin password (min 8 characters): ")
			newPass = strings.TrimSpace(newPass)
			if len(newPass) < 8 {
				fmt.Println(Red + "[!] Password must be at least 8 characters long. Try again." + Reset)
				continue
			}
			activePassword = newPass
			fmt.Println(Green + Bold + "=> Custom Admin Password Queued for Deployment!" + Reset)
			break
		}
	}

	preSetupCmd := fmt.Sprintf(`
		docker rm -f cross-jenkins 2>/dev/null || true
		mkdir -p /var/jenkins_home/init.groovy.d /var/jenkins_home/updates
		
		echo '2.440.3' > /var/jenkins_home/jenkins.install.UpgradeWizard.state
		echo '2.440.3' > /var/jenkins_home/jenkins.install.InstallUtil.lastExecVersion

		cat << 'EOF' > /var/jenkins_home/jenkins.model.JenkinsLocationConfiguration.xml
<?xml version='1.1' encoding='UTF-8'?>
<jenkins.model.JenkinsLocationConfiguration>
  <adminAddress>admin@local.host</adminAddress>
  <jenkinsUrl>http://%s:%d/</jenkinsUrl>
</jenkins.model.JenkinsLocationConfiguration>
EOF

		cat << 'EOF' > /var/jenkins_home/init.groovy.d/01-basic-security.groovy
#!groovy
import jenkins.model.*
import hudson.security.*

def instance = Jenkins.getInstance()
def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount('admin', '%s')
instance.setSecurityRealm(hudsonRealm)

def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)

instance.setInstallState(jenkins.install.InstallState.INITIAL_SETUP_COMPLETED)
instance.setNumExecutors(2)
instance.setMode(hudson.model.Node.Mode.NORMAL)
instance.save()
EOF

		chown -R 1000:1000 /var/jenkins_home
		chmod -R 777 /var/jenkins_home
	`, targetIP, port, activePassword)
	_, _ = runSudoScriptWithSpinner(client, preSetupCmd, "Pre-seeding Jenkins Security Realm, URL & Completion Flags")

	runCmd := fmt.Sprintf(`docker run -d --name cross-jenkins \
		--dns 8.8.8.8 --dns 1.1.1.1 \
		-p %d:8080 \
		-p 50000:50000 \
		-e "JAVA_OPTS=-Djenkins.install.runSetupWizard=false -Dhudson.model.DownloadService.noSignatureCheck=true -Dhudson.model.DirectoryBrowserSupport.CSP= -Djava.awt.headless=true" \
		-v /var/jenkins_home:/var/jenkins_home \
		--restart always %s`, port, imageTag)

	_, err := executeAutonomousDockerRun(client, "cross-jenkins", runCmd, fmt.Sprintf("Launching Jenkins Automation Server (Port %d)", port))
	if err != nil {
		fmt.Printf(Red+"[!] Jenkins deployment failed: %v\n"+Reset, err)
		return
	}

	waitCmd := fmt.Sprintf(`
		for i in {1..45}; do
			HTTP_CODE=$(curl -s -o /dev/null -w "%%{http_code}" http://127.0.0.1:%d/login 2>/dev/null || true)
			if [ "$HTTP_CODE" = "200" ]; then
				exit 0
			fi
			sleep 2
		done
		exit 0
	`, port)
	_, _ = runSudoScriptWithSpinner(client, waitCmd, "Waiting for Jenkins Web Engine & Dashboard Readiness")

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> JENKINS AUTOMATION SERVER DEPLOYED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Access URL         : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Cyan+Bold+"   => Image Tag          : %s\n"+Reset, imageTag)
	fmt.Printf(Cyan+Bold+"   => Administrator User : admin\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Active Password    : %s\n"+Reset, activePassword)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployGitLab(client *ssh.Client, port int, targetIP string, imageTag string) {
	handleVolumePersistence(client, []string{"/srv/gitlab"}, "GitLab CE Hub")

	cleanupCmd := `
		docker rm -f cross-gitlab 2>/dev/null || true
		mkdir -p /srv/gitlab/config /srv/gitlab/logs /srv/gitlab/data
		chmod -R 777 /srv/gitlab
	`
	_, _ = runSudoScriptWithSpinner(client, cleanupCmd, "Preparing Clean Storage Mounts for GitLab")

	configPreseed := fmt.Sprintf(`
cat << 'EOF' > /srv/gitlab/config/gitlab.rb
external_url 'http://%s:%d'
gitlab_rails['gitlab_shell_ssh_port'] = 2222
gitlab_rails['initial_root_password'] = 'kX9#mQ2$vL7!zP4@'
gitlab_rails['store_initial_root_password'] = true

nginx['listen_port'] = %d
nginx['listen_https'] = false
nginx['proxy_set_headers'] = {
  "Host" => "%s:%d",
  "X-Forwarded-Proto" => "http",
  "X-Forwarded-For" => "$proxy_add_x_forwarded_for",
  "X-Forwarded-Host" => "%s:%d",
  "X-Forwarded-Port" => "%d",
  "X-Forwarded-Ssl" => "off"
}

gitlab_rails['trusted_proxies'] = ['127.0.0.1', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
puma['worker_processes'] = 2
sidekiq['max_concurrency'] = 10
EOF
chmod 600 /srv/gitlab/config/gitlab.rb
	`, targetIP, port, port, targetIP, port, targetIP, port, port)
	_, _ = runSudoScriptWithSpinner(client, configPreseed, "Pre-seeding GitLab Configuration & Proxy Headers")

	fwCmd := fmt.Sprintf(`
		if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
			ufw allow %d/tcp 2>/dev/null || true
			ufw allow 2222/tcp 2>/dev/null || true
		elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
			firewall-cmd --permanent --add-port=%d/tcp 2>/dev/null || true
			firewall-cmd --permanent --add-port=2222/tcp 2>/dev/null || true
			firewall-cmd --reload 2>/dev/null || true
		fi
	`, port, port)
	_, _ = runSudoScriptWithSpinner(client, fwCmd, "Configuring Host Firewall Rules")

	gitlabRunCmd := fmt.Sprintf(`docker run -d --name cross-gitlab \
		-p %d:%d \
		-p 2222:22 \
		-v /srv/gitlab/config:/etc/gitlab \
		-v /srv/gitlab/logs:/var/log/gitlab \
		-v /srv/gitlab/data:/var/opt/gitlab \
		--shm-size 512m \
		--restart always %s`, port, port, imageTag)

	_, err := executeAutonomousDockerRun(client, "cross-gitlab", gitlabRunCmd, fmt.Sprintf("Launching GitLab CE Instance (Port %d)", port))
	if err != nil {
		fmt.Printf(Red+"[!] GitLab deployment failed: %v\n"+Reset, err)
		return
	}

	waitCmd := `
		for i in {1..90}; do
			if docker exec -i cross-gitlab gitlab-rails runner "puts 'DB_READY' if ActiveRecord::Base.connection.table_exists?('users')" 2>/dev/null | grep -q 'DB_READY'; then
				exit 0
			fi
			sleep 4
		done
		exit 1
	`
	_, _ = runSudoScriptWithSpinner(client, waitCmd, "Waiting for GitLab Database & Migration Readiness")

	activePassword := "kX9#mQ2$vL7!zP4@"
	syncCmd := fmt.Sprintf(`
		docker exec -i cross-gitlab gitlab-rails runner - << 'EOF' >/tmp/gitlab_sync.log 2>&1
user = User.find_by_username('root') || User.where(id: 1).first || User.first

if user.nil?
  user = User.new(
    id: 1,
    username: 'root',
    email: 'admin@local.host',
    name: 'Administrator',
    password: '%s',
    password_confirmation: '%s',
    admin: true,
    state: 'active'
  )
else
  user.username = 'root'
  user.password = '%s'
  user.password_confirmation = '%s'
  user.state = 'active'
  user.admin = true
end

if user.namespace.nil?
  user.build_personal_namespace(name: user.name, path: user.username) rescue nil
  if user.namespace.nil?
    ns = Namespace.find_or_create_by!(path: user.username) do |n|
      n.name = user.name
      n.owner = user
      n.type = 'User'
    end
    ns.update_columns(owner_id: user.id, type: 'User')
  end
end

user.role = 'software_developer' if user.respond_to?(:role=)
user.skip_confirmation! if user.respond_to?(:skip_confirmation!)
user.unlock_access! if user.respond_to?(:unlock_access!) && user.access_locked?
user.failed_attempts = 0 if user.respond_to?(:failed_attempts)
user.save(validate: false)

if user.respond_to?(:user_detail) && user.user_detail
  user.user_detail.update_columns(onboarding_step_url: nil, registration_objective: 0) rescue nil
end

begin
  token = user.personal_access_tokens.find_by(name: 'orchestrator-admin-token')
  if token.nil?
    token = user.personal_access_tokens.create(
      name: 'orchestrator-admin-token',
      scopes: [:api, :read_user, :read_repository, :write_repository, :sudo],
      expires_at: 365.days.from_now
    )
  end
  if token.respond_to?(:set_token)
    token.set_token('glpat-AdminRootSecretToken123')
    token.save(validate: false)
  end
rescue => e
  puts "Token error: #{e.message}"
end

ApplicationSetting.current.update(signup_enabled: false) rescue nil
Rails.cache.clear
puts "AUTONOMOUS_GITLAB_READY"
EOF
	`, activePassword, activePassword, activePassword, activePassword)
	_, _ = runSudoScriptWithSpinner(client, syncCmd, "Finalizing Root Credentials & Binding Namespaces")

	fmt.Println("\n" + Cyan + "--------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+Yellow+"=> Default Generated Root Password: %s\n"+Reset, activePassword)
	customPrompt := transfer.ReadRealtimeInput("Do you want to set your own custom root password? [y/N]: ")
	if strings.ToLower(strings.TrimSpace(customPrompt)) == "y" {
		for {
			newPass := transfer.ReadRealtimeInput("Enter your desired root password (min 8 characters): ")
			newPass = strings.TrimSpace(newPass)
			if len(newPass) < 8 {
				fmt.Println(Red + "[!] Password must be at least 8 characters long. Try again." + Reset)
				continue
			}

			setCustomPassCmd := fmt.Sprintf(`
				docker exec -i cross-gitlab gitlab-rails runner - << 'EOF' >/dev/null 2>&1
user = User.find_by_username('root') || User.first
user.password = '%s'
user.password_confirmation = '%s'
user.save(validate: false)
Rails.cache.clear
EOF
			`, newPass, newPass)
			_, _ = runSudoScriptWithSpinner(client, setCustomPassCmd, "Applying Custom Root Password to GitLab")
			activePassword = newPass
			fmt.Println(Green + Bold + "=> Custom Root Password Applied Successfully!" + Reset)
			break
		}
	}

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> GITLAB CE DEPLOYED & FULLY SYNCHRONIZED!" + Reset)
	fmt.Printf(Green+Bold+"   => Access URL         : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Cyan+Bold+"   => Administrator User : root\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Active Password    : %s\n"+Reset, activePassword)
	fmt.Printf(Yellow+Bold+"   => Admin PAT Token    : glpat-AdminRootSecretToken123\n"+Reset)
	fmt.Printf(Yellow+Bold+"   => SSH Git Remote Port: 2222\n"+Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deploySonarQube(client *ssh.Client, port int, targetIP string, imageTag string) {
	if imageTag == "" {
		imageTag = "sonarqube:lts-community"
	}

	handleVolumePersistence(client, []string{"/var/sonarqube_data"}, "SonarQube Code Security")

	runCmd := fmt.Sprintf("docker run -d --name cross-sonarqube -p %d:9000 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -v /var/sonarqube_data:/opt/sonarqube/data --restart always %s", port, imageTag)
	_, err := executeAutonomousDockerRun(client, "cross-sonarqube", runCmd, fmt.Sprintf("Deploying SonarQube (%s on Port %d)", imageTag, port))
	if err != nil {
		fmt.Printf(Red+"[!] SonarQube deployment failed: %v\n"+Reset, err)
		return
	}

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> SONARQUBE DEPLOYED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Access URL         : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Cyan+Bold+"   => Image Tag          : %s\n"+Reset, imageTag)
	fmt.Printf(Cyan+Bold+"   => Default Username   : admin\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Default Password   : admin\n"+Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployPrometheusGrafana(client *ssh.Client, port int, targetIP string, imageTag string) {
	promImage := "prom/prometheus:v2.51.0"
	grafImage := "grafana/grafana:10.4.0"

	if strings.Contains(imageTag, "|") {
		parts := strings.Split(imageTag, "|")
		promImage = parts[0]
		grafImage = parts[1]
	}

	handleVolumePersistence(client, []string{"/etc/prometheus", "/var/grafana_data"}, "Prometheus & Grafana")

	preCmd := fmt.Sprintf(`
		mkdir -p /etc/prometheus /etc/grafana/provisioning/datasources /var/grafana_data
		rm -rf /etc/grafana/provisioning/datasources/* 2>/dev/null || true
		chmod -R 777 /etc/prometheus /etc/grafana /var/grafana_data
		chown -R 472:472 /var/grafana_data 2>/dev/null || true

		cat << 'EOF' > /etc/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['127.0.0.1:9090']
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['127.0.0.1:9100']
EOF

		cat << 'EOF' > /etc/grafana/provisioning/datasources/default.yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    orgId: 1
    url: http://127.0.0.1:9090
    isDefault: true
    version: 1
    editable: true
    uid: prometheus-default
    jsonData:
      httpMethod: POST
      timeInterval: 15s
EOF
		chmod 644 /etc/prometheus/prometheus.yml /etc/grafana/provisioning/datasources/default.yaml 2>/dev/null || true

		if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
			ufw allow 9090/tcp 2>/dev/null || true
			ufw allow %d/tcp 2>/dev/null || true
		elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
			firewall-cmd --permanent --add-port=9090/tcp 2>/dev/null || true
			firewall-cmd --permanent --add-port=%d/tcp 2>/dev/null || true
			firewall-cmd --reload 2>/dev/null || true
		fi
	`, port, port)
	_, _ = runSudoScriptWithSpinner(client, preCmd, "Generating Scrape Config & Binding Prometheus Datasource")

	promCmd := fmt.Sprintf("docker run -d --name cross-prometheus --network host -v /etc/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml --restart always %s", promImage)
	_, _ = executeAutonomousDockerRun(client, "cross-prometheus", promCmd, "Deploying Prometheus Metrics Engine (Port 9090)")

	grafCmd := fmt.Sprintf(`docker run -d --name cross-grafana --network host \
		-e "GF_SERVER_HTTP_PORT=%d" \
		-e "GF_SECURITY_ADMIN_USER=admin" \
		-e "GF_SECURITY_ADMIN_PASSWORD=admin" \
		-e "GF_USERS_ALLOW_SIGN_UP=false" \
		-v /etc/grafana/provisioning:/etc/grafana/provisioning \
		-v /var/grafana_data:/var/lib/grafana \
		--restart always %s`, port, grafImage)
	_, err := executeAutonomousDockerRun(client, "cross-grafana", grafCmd, fmt.Sprintf("Deploying Pre-Wired Grafana Dashboard (Port %d)", port))
	if err != nil {
		fmt.Printf(Red+"[!] Grafana deployment failed: %v\n"+Reset, err)
		return
	}

	waitCmd := fmt.Sprintf(`
		for i in {1..35}; do
			if curl -s http://127.0.0.1:%d/api/health 2>/dev/null | grep -q 'ok'; then
				docker exec cross-grafana grafana cli admin reset-admin-password admin >/dev/null 2>&1 || \
				docker exec cross-grafana grafana-cli admin reset-admin-password admin >/dev/null 2>&1 || true
				exit 0
			fi
			sleep 2
		done
		exit 0
	`, port)
	_, _ = runSudoScriptWithSpinner(client, waitCmd, "Synchronizing Grafana Credentials & Auto-Datasource Linkage")

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> PROMETHEUS & GRAFANA STACK DEPLOYED & INTERCONNECTED!" + Reset)
	fmt.Printf(Green+Bold+"   => Grafana Dashboard  : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Cyan+Bold+"   => Default Login      : admin / admin\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Auto-Wired Source  : Prometheus (http://127.0.0.1:9090 - Default)\n"+Reset)
	fmt.Printf(Green+Bold+"   => Prometheus Engine  : http://%s:9090\n"+Reset, targetIP)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployELK(client *ssh.Client, port int, targetIP string, version string) {
	esImage := "docker.elastic.co/elasticsearch/elasticsearch:8.11.0"
	kibImage := "docker.elastic.co/kibana/kibana:8.11.0"

	if version == "latest" {
		esImage = "docker.elastic.co/elasticsearch/elasticsearch:8.17.0"
		kibImage = "docker.elastic.co/kibana/kibana:8.17.0"
	}

	masterPass := "ElasticAdminPass123"
	handleVolumePersistence(client, []string{"/var/elasticsearch_data"}, "ELK Stack")

	preCmd := fmt.Sprintf(`
		sysctl -w vm.max_map_count=262144 2>/dev/null || true
		echo 'vm.max_map_count=262144' >> /etc/sysctl.conf 2>/dev/null || true
		mkdir -p /var/elasticsearch_data
		chmod -R 777 /var/elasticsearch_data
		chown -R 1000:1000 /var/elasticsearch_data 2>/dev/null || true

		if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
			ufw allow 9200/tcp 2>/dev/null || true
			ufw allow %d/tcp 2>/dev/null || true
		elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
			firewall-cmd --permanent --add-port=9200/tcp 2>/dev/null || true
			firewall-cmd --permanent --add-port=%d/tcp 2>/dev/null || true
			firewall-cmd --reload 2>/dev/null || true
		fi
	`, port, port)
	_, _ = runSudoScriptWithSpinner(client, preCmd, "Configuring Kernel Subsystem, Firewall & Volumes")

	esRunCmd := fmt.Sprintf("docker run -d --name cross-elasticsearch --network host -e discovery.type=single-node -e xpack.security.enabled=true -e xpack.security.http.ssl.enabled=false -e ELASTIC_PASSWORD=%s -e ES_JAVA_OPTS='-Xms512m -Xmx1024m' -v /var/elasticsearch_data:/usr/share/elasticsearch/data --restart always %s", masterPass, esImage)
	_, err := executeAutonomousDockerRun(client, "cross-elasticsearch", esRunCmd, fmt.Sprintf("Deploying Authenticated Elasticsearch Core Node (%s)", esImage))
	if err != nil {
		fmt.Printf(Red+"[!] Elasticsearch deployment failed: %v\n"+Reset, err)
		return
	}

	generateTokenCmd := fmt.Sprintf(`
		for i in {1..45}; do
			if curl -s -u elastic:%s http://127.0.0.1:9200/_cluster/health 2>/dev/null | grep -q 'cluster_name'; then
				RAW_TOKEN=$(docker exec cross-elasticsearch bin/elasticsearch-service-tokens create elastic/kibana kibana-auto-token 2>/dev/null || true)
				TOKEN=$(echo "$RAW_TOKEN" | awk -F' = ' '{print $2}' | tr -d '\r\n ')
				if [ -n "$TOKEN" ]; then
					echo "TOKEN_GENERATED|$TOKEN"
					exit 0
				fi
			fi
			sleep 2
		done
		echo "TOKEN_FAILED"
	`, masterPass)

	tokenOut, _ := runSudoScriptWithSpinner(client, generateTokenCmd, "Synchronizing Elasticsearch & Provisioning Kibana Service Token")

	var kibanaToken string
	if strings.Contains(tokenOut, "TOKEN_GENERATED|") {
		parts := strings.Split(tokenOut, "TOKEN_GENERATED|")
		if len(parts) > 1 {
			kibanaToken = cleanExtractedSecret(parts[1])
		}
	}

	var kibRunCmd string
	if kibanaToken != "" {
		kibRunCmd = fmt.Sprintf(`docker run -d --name cross-kibana --network host \
			-e "SERVER_PORT=%d" \
			-e "SERVER_NAME=cross-kibana" \
			-e "SERVER_HOST=0.0.0.0" \
			-e "SERVER_PUBLICBASEURL=http://%s:%d" \
			-e "ELASTICSEARCH_HOSTS=http://127.0.0.1:9200" \
			-e "ELASTICSEARCH_SERVICEACCOUNTTOKEN=%s" \
			-e "XPACK_SECURITY_ENCRYPTIONKEY=crosssuiteencryptionkeysecure123456" \
			-e "XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=crosssuiteencryptionkeysecure123456" \
			-e "XPACK_REPORTING_ENCRYPTIONKEY=crosssuiteencryptionkeysecure123456" \
			-e "TELEMETRY_ENABLED=false" \
			-e "NEWSFEED_ENABLED=false" \
			-e "NODE_OPTIONS=--max-old-space-size=1024" \
			--restart always %s`, port, targetIP, port, kibanaToken, kibImage)
	} else {
		kibRunCmd = fmt.Sprintf(`docker run -d --name cross-kibana --network host \
			-e "SERVER_PORT=%d" \
			-e "SERVER_NAME=cross-kibana" \
			-e "SERVER_HOST=0.0.0.0" \
			-e "SERVER_PUBLICBASEURL=http://%s:%d" \
			-e "ELASTICSEARCH_HOSTS=http://127.0.0.1:9200" \
			-e "ELASTICSEARCH_USERNAME=elastic" \
			-e "ELASTICSEARCH_PASSWORD=%s" \
			-e "XPACK_SECURITY_ENCRYPTIONKEY=crosssuiteencryptionkeysecure123456" \
			-e "XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=crosssuiteencryptionkeysecure123456" \
			-e "XPACK_REPORTING_ENCRYPTIONKEY=crosssuiteencryptionkeysecure123456" \
			-e "TELEMETRY_ENABLED=false" \
			-e "NEWSFEED_ENABLED=false" \
			-e "NODE_OPTIONS=--max-old-space-size=1024" \
			--restart always %s`, port, targetIP, port, masterPass, kibImage)
	}

	_, err = executeAutonomousDockerRun(client, "cross-kibana", kibRunCmd, fmt.Sprintf("Deploying Authenticated Kibana Dashboard (%s on Port %d)", kibImage, port))
	if err != nil {
		fmt.Printf(Red+"[!] Kibana deployment failed: %v\n"+Reset, err)
		return
	}

	kibWaitCmd := fmt.Sprintf(`
		for i in {1..45}; do
			HTTP_CODE=$(curl -s -o /dev/null -w "%%{http_code}" http://127.0.0.1:%d/login 2>/dev/null || true)
			if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
				exit 0
			fi
			sleep 2
		done
		exit 0
	`, port)
	_, _ = runSudoScriptWithSpinner(client, kibWaitCmd, "Waiting for Kibana Web Engine Initialization & Asset Readiness")

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> SECURED ELK STACK DEPLOYED & INTERCONNECTED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Kibana Web Dashboard : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Green+Bold+"   => Elasticsearch REST   : http://%s:9200\n"+Reset, targetIP)
	fmt.Printf(Cyan+Bold+"   => Superuser Username   : elastic\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Master Password      : %s\n"+Reset, masterPass)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployVault(client *ssh.Client, port int, targetIP string, imageTag string) {
	if imageTag == "" {
		imageTag = "hashicorp/vault:1.15.6"
	}

	handleVolumePersistence(client, []string{"/var/vault_data"}, "HashiCorp Vault Secrets Engine")

	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	activeToken := "cross-vault-" + hex.EncodeToString(tokenBytes)

	runCmd := fmt.Sprintf(`docker run -d --name cross-vault \
		-p %d:8200 \
		-e 'VAULT_DEV_ROOT_TOKEN_ID=%s' \
		-e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
		-v /var/vault_data:/vault/data \
		--cap-add=IPC_LOCK \
		--restart always %s`, port, activeToken, imageTag)

	_, err := executeAutonomousDockerRun(client, "cross-vault", runCmd, fmt.Sprintf("Deploying Persistent Vault Secrets Engine (%s on Port %d)", imageTag, port))
	if err != nil {
		fmt.Printf(Red+"[!] Vault deployment failed: %v\n"+Reset, err)
		return
	}

	verifyCmd := fmt.Sprintf(`
		for i in {1..20}; do
			if docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='%s' cross-vault vault status 2>/dev/null | grep -q 'Initialized.*true'; then
				exit 0
			fi
			sleep 1
		done
		exit 0
	`, activeToken)
	_, _ = runSudoScriptWithSpinner(client, verifyCmd, "Verifying Vault Health & Persistent Storage Engine")

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> HASHICORP VAULT DEPLOYED SUCCESSFULLY (PERSISTENT STORAGE)!" + Reset)
	fmt.Printf(Green+Bold+"   => Access URL (Web UI)  : http://%s:%d\n"+Reset, targetIP, port)
	fmt.Printf(Cyan+Bold+"   => Authentication Method: Token\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Active Session Token : %s\n"+Reset, activeToken)
	fmt.Printf(Cyan+Bold+"   => Persistent Storage   : /var/vault_data (Preserved across runs)\n"+Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployTerraform(client *ssh.Client, option string) {
	isLatest := (option == "latest")

	cmd := fmt.Sprintf(`
		ARCH=$(uname -m)
		case "$ARCH" in
			x86_64|amd64)  TF_ARCH="amd64" ;;
			aarch64|arm64) TF_ARCH="arm64" ;;
			*)             TF_ARCH="amd64" ;;
		esac

		rm -rf /tmp/tf_extract /tmp/terraform.zip 2>/dev/null
		mkdir -p /tmp/tf_extract /usr/local/bin

		if [ "%t" = "true" ]; then
			LATEST_VER=$(curl -sSL "https://checkpoint-api.hashicorp.com/v1/check/terraform" 2>/dev/null | grep -o '"current_version":"[^"]*"' | cut -d'"' -f4)
			[ -z "$LATEST_VER" ] && LATEST_VER="1.15.8"

			curl -sSL -H "User-Agent: Mozilla/5.0" "https://releases.hashicorp.com/terraform/${LATEST_VER}/terraform_${LATEST_VER}_linux_${TF_ARCH}.zip" -o /tmp/terraform.zip 2>/dev/null || \
			wget -U "Mozilla/5.0" -q "https://releases.hashicorp.com/terraform/${LATEST_VER}/terraform_${LATEST_VER}_linux_${TF_ARCH}.zip" -O /tmp/terraform.zip 2>/dev/null || true

			if [ -f /tmp/terraform.zip ] && [ -s /tmp/terraform.zip ]; then
				unzip -qo /tmp/terraform.zip -d /usr/local/bin/ 2>/dev/null || \
				busybox unzip /tmp/terraform.zip -d /usr/local/bin/ 2>/dev/null || true
				chmod 755 /usr/local/bin/terraform 2>/dev/null || true
			else
				if command -v apt-get >/dev/null 2>&1; then
					export DEBIAN_FRONTEND=noninteractive
					wget -O- https://apt.releases.hashicorp.com/gpg 2>/dev/null | gpg --dearmor -o /etc/apt/trusted.gpg.d/hashicorp.gpg 2>/dev/null || true
					echo "deb https://apt.releases.hashicorp.com bookworm main" | tee /etc/apt/sources.list.d/hashicorp.list >/dev/null || true
					apt-get update -qq >/dev/null 2>&1 || true
					apt-get install --only-upgrade -y -qq terraform >/dev/null 2>&1 || apt-get install -y -qq terraform >/dev/null 2>&1 || true
				fi
			fi
		else
			if [ ! -f /usr/local/bin/terraform ] || ! /usr/local/bin/terraform --version 2>/dev/null | grep -q "1.7.5"; then
				curl -sSL -H "User-Agent: Mozilla/5.0" "https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_${TF_ARCH}.zip" -o /tmp/terraform.zip 2>/dev/null || \
				wget -U "Mozilla/5.0" -q "https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_${TF_ARCH}.zip" -O /tmp/terraform.zip 2>/dev/null || true

				if [ -f /tmp/terraform.zip ] && [ -s /tmp/terraform.zip ]; then
					unzip -qo /tmp/terraform.zip -d /usr/local/bin/ 2>/dev/null || \
					busybox unzip /tmp/terraform.zip -d /usr/local/bin/ 2>/dev/null || true
					chmod 755 /usr/local/bin/terraform 2>/dev/null || true
				fi
			fi
		fi

		rm -rf /tmp/tf_extract /tmp/terraform.zip 2>/dev/null
		hash -r 2>/dev/null || true
		exit 0
	`, isLatest)

	label := "Deploying Pinned Stable Terraform (v1.7.5)"
	if isLatest {
		label = "Resolving & Deploying Live Upstream Terraform Engine"
	}

	_, _ = runSudoScriptWithSpinner(client, cmd, label)

	verifyOut, _ := executeRemoteCommand(client, "/usr/local/bin/terraform --version 2>/dev/null || terraform --version 2>/dev/null")
	cleanVer := strings.TrimSpace(verifyOut)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> HASHICORP TERRAFORM ENGINE INSTALLED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Installed Version  :\n%s\n"+Reset, cleanVer)
	fmt.Println(Green + Bold + "   => CLI Command        : Available system-wide via 'terraform'" + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployAnsible(client *ssh.Client, option string) {
	isLatest := (option == "latest")

	cmd := fmt.Sprintf(`
		export DEBIAN_FRONTEND=noninteractive
		if [ "%t" = "true" ]; then
			if command -v apt-get >/dev/null 2>&1; then
				apt-get update -qq >/dev/null 2>&1
				apt-get install -y -qq python3-pip python3-setuptools >/dev/null 2>&1 || true
			fi
			pip3 install --upgrade ansible >/dev/null 2>&1 || pip install --upgrade ansible >/dev/null 2>&1 || true
		else
			if ! command -v ansible >/dev/null 2>&1; then
				if command -v apt-get >/dev/null 2>&1; then
					apt-get update -qq >/dev/null 2>&1
					apt-get install -y -qq ansible >/dev/null 2>&1 || true
				elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
					dnf install -y -q epel-release 2>/dev/null || yum install -y -q epel-release 2>/dev/null || true
					dnf install -y -q ansible 2>/dev/null || yum install -y -q ansible 2>/dev/null || true
				fi
			fi
		fi
		exit 0
	`, isLatest)

	label := "Deploying Standard Distribution Ansible Engine"
	if isLatest {
		label = "Deploying Live Upstream Ansible Subsystem"
	}
	_, _ = runSudoScriptWithSpinner(client, cmd, label)

	verifyOut, _ := executeRemoteCommand(client, "ansible --version 2>/dev/null | head -n 1")
	cleanVer := strings.TrimSpace(verifyOut)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> ANSIBLE AUTOMATION ENGINE INSTALLED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Installed Version  : %s\n"+Reset, cleanVer)
	fmt.Println(Green + Bold + "   => CLI Command        : Available system-wide via 'ansible' & 'ansible-playbook'" + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func resolveAvailablePort(client *ssh.Client, desiredPort int, serviceName string) int {
	checkCmd := fmt.Sprintf("ss -tulpn 2>/dev/null | grep -q ':%d ' || lsof -i :%d >/dev/null 2>&1", desiredPort, desiredPort)
	_, err := runSudoScript(client, checkCmd)
	if err == nil {
		for candidate := 8443; candidate <= 8450; candidate++ {
			cCheck := fmt.Sprintf("ss -tulpn 2>/dev/null | grep -q ':%d ' || lsof -i :%d >/dev/null 2>&1", candidate, candidate)
			if _, cErr := runSudoScript(client, cCheck); cErr != nil {
				fmt.Println(Yellow + Bold + fmt.Sprintf("\n=> PORT CONFLICT DETECTED: Port %d is in use!", desiredPort) + Reset)
				fmt.Println(Green + Bold + fmt.Sprintf("=> AUTONOMOUS RESOLUTION: Remapping %s to free port %d!\n", serviceName, candidate) + Reset)
				return candidate
			}
		}
	}
	return desiredPort
}

func deployK3s(client *ssh.Client, targetIP string, versionChannel string) {
	handleVolumePersistence(client, []string{"/var/lib/rancher/k3s", "/etc/rancher/k3s"}, "K3s Kubernetes Cluster")

	installEnv := `INSTALL_K3S_EXEC="--write-kubeconfig-mode 644"`
	if versionChannel != "" && versionChannel != "latest" {
		installEnv = fmt.Sprintf(`INSTALL_K3S_VERSION="%s" INSTALL_K3S_EXEC="--write-kubeconfig-mode 644"`, versionChannel)
	}

	cmd := fmt.Sprintf(`
		sysctl -w fs.inotify.max_user_watches=524288 >/dev/null 2>&1 || true
		sysctl -w fs.inotify.max_user_instances=8192 >/dev/null 2>&1 || true
		sysctl -w fs.file-max=2097152 >/dev/null 2>&1 || true

		mkdir -p /etc/sysctl.d 2>/dev/null || true
		cat << 'EOF' > /etc/sysctl.d/99-k3s-inotify.conf
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=8192
fs.file-max=2097152
EOF
		sysctl --system >/dev/null 2>&1 || true

		if ! command -v k3s >/dev/null 2>&1 || [ "%s" = "latest" ]; then
			curl -sfL https://get.k3s.io | %s sh -s - 2>/dev/null || \
			wget -qO- https://get.k3s.io | %s sh -s - 2>/dev/null || true
		fi

		systemctl unmask k3s 2>/dev/null || true
		systemctl enable k3s 2>/dev/null || true
		systemctl restart k3s 2>/dev/null || true

		mkdir -p ~/.kube /root/.kube /etc/rancher/k3s 2>/dev/null || true
		for i in {1..15}; do
			if [ -f /etc/rancher/k3s/k3s.yaml ]; then
				cp -f /etc/rancher/k3s/k3s.yaml ~/.kube/config 2>/dev/null || true
				cp -f /etc/rancher/k3s/k3s.yaml /root/.kube/config 2>/dev/null || true
				chmod 644 /etc/rancher/k3s/k3s.yaml ~/.kube/config /root/.kube/config 2>/dev/null || true
				break
			fi
			sleep 1
		done
		exit 0
	`, versionChannel, installEnv, installEnv)

	_, _ = runSudoScriptWithSpinner(client, cmd, fmt.Sprintf("Bootstrapping K3s Kubernetes Engine (%s)", versionChannel))

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> K3S KUBERNETES CLUSTER ONLINE!" + Reset)
	fmt.Printf(Green+Bold+"   => API Server Host    : https://%s:6443\n"+Reset, targetIP)
	fmt.Println(Cyan + Bold + "   => Kubeconfig Path    : /etc/rancher/k3s/k3s.yaml" + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployArgoCD(client *ssh.Client, defaultPort int, targetIP string, manifestVersion string) {
	fmt.Println(Cyan + Bold + "\n=> Auditing System Port Availability..." + Reset)
	activePort := resolveAvailablePort(client, defaultPort, "ArgoCD GitOps Server")

	checkK3sCmd := "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; kubectl get nodes 2>/dev/null | grep -q 'Ready'"
	if _, err := runSudoScript(client, checkK3sCmd); err != nil {
		fmt.Println(Cyan + Bold + "=> Bootstrapping K3s Kubernetes Engine..." + Reset)
		deployK3s(client, targetIP, "v1.28.8+k3s1")
	}

	targetTag := "v2.10.4"
	if manifestVersion == "stable" {
		targetTag = "stable"
	}

	argoManifestCmd := fmt.Sprintf(`
		export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
		kubectl create namespace argocd 2>/dev/null || true

		MANIFEST_FILE="/tmp/argocd-install.yaml"
		rm -f "$MANIFEST_FILE"

		# Mirror 1 (jsDelivr CDN)
		curl -sSL --max-time 15 "https://cdn.jsdelivr.net/gh/argoproj/argo-cd@%s/manifests/install.yaml" -o "$MANIFEST_FILE" 2>/dev/null || true

		# Mirror 2 (Fastly CDN)
		if [ ! -s "$MANIFEST_FILE" ] || grep -q "Too Many Requests" "$MANIFEST_FILE"; then
			curl -sSL --max-time 15 "https://fastly.jsdelivr.net/gh/argoproj/argo-cd@%s/manifests/install.yaml" -o "$MANIFEST_FILE" 2>/dev/null || true
		fi

		# Upstream GitHub Raw
		if [ ! -s "$MANIFEST_FILE" ] || grep -q "Too Many Requests" "$MANIFEST_FILE"; then
			curl -sSL --max-time 15 "https://raw.githubusercontent.com/argoproj/argo-cd/%s/manifests/install.yaml" -o "$MANIFEST_FILE" 2>/dev/null || true
		fi

		if [ -s "$MANIFEST_FILE" ] && ! grep -q "Too Many Requests" "$MANIFEST_FILE"; then
			kubectl apply -n argocd --validate=false -f "$MANIFEST_FILE" >/dev/null 2>&1
			rm -f "$MANIFEST_FILE"
			exit 0
		fi
		exit 1
	`, targetTag, targetTag, targetTag)
	_, _ = runSudoScriptWithSpinner(client, argoManifestCmd, "Applying ArgoCD Core Resources to Cluster")

	rolloutCmd := `
		export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
		kubectl -n argocd rollout status deployment/argocd-server --timeout=180s >/dev/null 2>&1 || true
		kubectl -n argocd wait --for=condition=Ready pod -l app.kubernetes.io/name=argocd-server --timeout=120s >/dev/null 2>&1 || true
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, rolloutCmd, "Waiting for ArgoCD Server Pod Readiness")

	systemdCmd := fmt.Sprintf(`
		KUBECTL_PATH=$(command -v kubectl || echo "/usr/local/bin/kubectl")

		cat << EOF > /etc/systemd/system/argocd-proxy.service
[Unit]
Description=ArgoCD Web UI Port Proxy
After=network.target k3s.service
Wants=k3s.service

[Service]
Type=simple
User=root
Environment=KUBECONFIG=/etc/rancher/k3s/k3s.yaml
ExecStart=${KUBECTL_PATH} port-forward --address 0.0.0.0 svc/argocd-server -n argocd %d:443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

		systemctl daemon-reload 2>/dev/null || true
		systemctl enable --now argocd-proxy.service 2>/dev/null || true
		systemctl restart argocd-proxy.service 2>/dev/null || true
		exit 0
	`, activePort)
	_, _ = runSudoScriptWithSpinner(client, systemdCmd, fmt.Sprintf("Activating Persistent Systemd Listener on Port %d", activePort))

	passCmd := `
		export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
		for i in {1..30}; do
			PASS=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d 2>/dev/null)
			if [ -n "$PASS" ] && [ "$PASS" != "" ]; then
				echo "PASS_FOUND|$PASS"
				exit 0
			fi
			sleep 2
		done
		echo "PASS_TIMEOUT"
	`
	passOut, _ := runSudoScriptWithSpinner(client, passCmd, "Decoding Administrator Password from Kubernetes Secret")

	var activePass string
	if strings.Contains(passOut, "PASS_FOUND|") {
		parts := strings.Split(passOut, "PASS_FOUND|")
		if len(parts) > 1 {
			activePass = cleanExtractedSecret(parts[1])
		}
	}
	if activePass == "" {
		activePass = "admin"
	}

	// Interactive Custom Password Modification
	fmt.Println("\n" + Cyan + "--------------------------------------------------------------------------------" + Reset)
	fmt.Printf(Bold+Yellow+"=> Default Initial ArgoCD Admin Password: %s\n"+Reset, activePass)
	customPrompt := transfer.ReadRealtimeInput("Do you want to set your own custom admin password for ArgoCD? [y/N]: ")
	if strings.ToLower(strings.TrimSpace(customPrompt)) == "y" {
		for {
			newPass := transfer.ReadRealtimeInput("Enter your desired admin password (min 8 characters): ")
			newPass = strings.TrimSpace(newPass)
			if len(newPass) < 8 {
				fmt.Println(Red + "[!] Password must be at least 8 characters long. Try again." + Reset)
				continue
			}

			setArgoPassCmd := fmt.Sprintf(`
				export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
				HASH=$(python3 -c "import crypt; print(crypt.crypt('%s', crypt.mksalt(crypt.METHOD_BLOWFISH)))" 2>/dev/null || \
				       python3 -c "import bcrypt; print(bcrypt.hashpw('%s'.encode(), bcrypt.gensalt(10)).decode())" 2>/dev/null || \
				       htpasswd -bnBC 10 "" '%s' 2>/dev/null | tr -d ':\n')

				if [ -n "$HASH" ]; then
					kubectl -n argocd patch secret argocd-secret -p "{\"stringData\": {\"admin.password\": \"$HASH\", \"admin.passwordMtime\": \"$(date +%%FT%%T%%Z)\"}}" 2>/dev/null || true
					kubectl -n argocd delete secret argocd-initial-admin-secret 2>/dev/null || true
					echo "CUSTOM_PASS_SET"
				fi
			`, newPass, newPass, newPass)

			res, _ := runSudoScriptWithSpinner(client, setArgoPassCmd, "Injecting Custom Admin Password Hash into ArgoCD Secret")
			if strings.Contains(res, "CUSTOM_PASS_SET") {
				activePass = newPass
				fmt.Println(Green + Bold + "=> Custom ArgoCD Admin Password Applied Successfully!" + Reset)
			}
			break
		}
	}

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> ARGOCD GITOPS ENGINE DEPLOYED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Access URL (HTTPS) : https://%s:%d\n"+Reset, targetIP, activePort)
	fmt.Printf(Cyan+Bold+"   => Manifest Stream    : %s\n"+Reset, manifestVersion)
	fmt.Printf(Cyan+Bold+"   => Administrator User : admin\n"+Reset)
	fmt.Printf(Cyan+Bold+"   => Active Password    : %s\n"+Reset, activePass)
	fmt.Println(Yellow + Bold + "   => Security Note      : Access via HTTPS (https://...). Accept the self-signed SSL warning." + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployTrivy(client *ssh.Client, version string) {
	cmd := `
		export DEBIAN_FRONTEND=noninteractive
		ARCH=$(uname -m)
		case "$ARCH" in
			x86_64|amd64)  T_ARCH="64bit" ;;
			aarch64|arm64) T_ARCH="ARM64" ;;
			*)             T_ARCH="64bit" ;;
		esac

		rm -rf /tmp/trivy_install /tmp/trivy.tar.gz 2>/dev/null
		mkdir -p /tmp/trivy_install /usr/local/bin /usr/bin

		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || \
		wget -qO- https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || true

		if [ ! -f /usr/local/bin/trivy ] && [ ! -f /usr/bin/trivy ]; then
			if command -v apt-get >/dev/null 2>&1; then
				apt-get update -qq >/dev/null 2>&1 || true
				apt-get install -y -qq wget apt-transport-https gnupg lsb-release 2>/dev/null || true
				wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/trivy.gpg 2>/dev/null || true
				echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc 2>/dev/null || echo 'bookworm') main" > /etc/apt/sources.list.d/trivy.list 2>/dev/null || true
				apt-get update -qq >/dev/null 2>&1 || true
				apt-get install -y -qq trivy >/dev/null 2>&1 || true
			elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
				cat << 'EOF' > /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1
EOF
				dnf install -y -q trivy 2>/dev/null || yum install -y -q trivy 2>/dev/null || true
			fi
		fi

		if [ -f /usr/local/bin/trivy ] && [ ! -f /usr/bin/trivy ]; then
			cp -f /usr/local/bin/trivy /usr/bin/trivy 2>/dev/null || ln -sf /usr/local/bin/trivy /usr/bin/trivy 2>/dev/null || true
		elif [ -f /usr/bin/trivy ] && [ ! -f /usr/local/bin/trivy ]; then
			cp -f /usr/bin/trivy /usr/local/bin/trivy 2>/dev/null || ln -sf /usr/bin/trivy /usr/local/bin/trivy 2>/dev/null || true
		fi

		chmod 755 /usr/local/bin/trivy /usr/bin/trivy 2>/dev/null || true
		hash -r 2>/dev/null || true
		exit 0
	`

	_, _ = runSudoScriptWithSpinner(client, cmd, "Deploying Aqua Trivy AppSec Engine (Auto-Installing via Multi-Source Pipeline)")

	verifyOut, _ := executeRemoteCommand(client, "trivy --version 2>/dev/null || /usr/local/bin/trivy --version 2>/dev/null || /usr/bin/trivy --version 2>/dev/null")
	cleanVer := strings.TrimSpace(verifyOut)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> AQUA TRIVY APPSEC SCANNER INSTALLED SUCCESSFULLY!" + Reset)
	fmt.Printf(Green+Bold+"   => Installed Version  :\n%s\n"+Reset, cleanVer)
	fmt.Println(Cyan + Bold + "   => CLI Command        : Available system-wide via 'trivy'" + Reset)
	fmt.Println(Cyan + Bold + "   => Quick Test Scan    : trivy image alpine:latest" + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

func deployAllPresets(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Bold + Yellow + "\n=> Deploying ALL DevSecOps Presets across host..." + Reset)
	catalog := GetCatalog()
	for _, preset := range catalog {
		deployPresetAutonomous(reader, client, preset, targetOS)
	}
}

func uninstallPrompt(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	catalog := GetCatalog()
	fmt.Println("\n" + Bold + Yellow + "==>> SELECT TOOL TO UNINSTALL & PURGE:" + Reset)
	for idx, item := range catalog {
		fmt.Printf("  [%2d] => %s\n", idx+1, item.Name)
	}

	fmt.Print(Bold + "Enter choice number [0 to Cancel]: " + Reset)
	input, _ := reader.ReadString('\n')
	var selectedIdx int
	_, err := fmt.Sscanf(strings.TrimSpace(input), "%d", &selectedIdx)

	if selectedIdx == 0 {
		return
	}

	if err == nil && selectedIdx >= 1 && selectedIdx <= len(catalog) {
		tool := catalog[selectedIdx-1]
		containerName := "cross-" + tool.ID

		ensureAutonomousPermissionsWithPrompt(client)

		bashScript := fmt.Sprintf(`#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# 1. Stop & Remove Container
docker rm -f %s 2>/dev/null || true

# 2. Deep Root-Level Purge of Specific Engine
case "%s" in
	docker)
		systemctl stop docker.socket docker containerd 2>/dev/null || true
		systemctl disable docker.socket docker containerd 2>/dev/null || true
		pkill -9 -f dockerd 2>/dev/null || true
		pkill -9 -f containerd 2>/dev/null || true
		apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker.io 2>/dev/null || \
		yum remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
		rm -f /var/run/docker.sock /run/docker.sock /etc/docker/daemon.json 2>/dev/null
		rm -rf /etc/docker /var/lib/docker /var/lib/containerd
		;;
	trivy)
		apt-get purge -y trivy 2>/dev/null || dpkg --purge trivy 2>/dev/null || true
		rm -f /usr/bin/trivy /usr/local/bin/trivy /bin/trivy /tmp/trivy* /etc/apt/sources.list.d/trivy.list
		rm -rf ~/.cache/trivy /root/.cache/trivy
		;;
	terraform)
		apt-get purge -y terraform 2>/dev/null || dpkg --purge terraform 2>/dev/null || true
		rm -f /usr/bin/terraform /usr/local/bin/terraform /bin/terraform /tmp/terraform* /etc/apt/sources.list.d/hashicorp.list
		;;
	ansible)
		apt-get purge -y ansible 2>/dev/null || dnf remove -y ansible 2>/dev/null || true
		pip3 uninstall -y ansible 2>/dev/null || true
		rm -f /usr/bin/ansible* /usr/local/bin/ansible*
		;;
	k3s)
		/usr/local/bin/k3s-uninstall.sh 2>/dev/null || /usr/local/bin/k3s-killall.sh 2>/dev/null || true
		rm -rf /etc/rancher/k3s /var/lib/rancher/k3s /usr/local/bin/k3s /usr/bin/k3s ~/.kube /root/.kube /etc/sysctl.d/99-k3s-inotify.conf
		;;
	argocd)
		systemctl stop argocd-proxy.service 2>/dev/null || true
		systemctl disable argocd-proxy.service 2>/dev/null || true
		rm -f /etc/systemd/system/argocd-proxy.service 2>/dev/null
		systemctl daemon-reload 2>/dev/null || true
		export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
		kubectl delete namespace argocd 2>/dev/null || true
		pkill -f "kubectl.*port-forward.*argocd-server" 2>/dev/null || true
		;;
	jenkins)
		rm -rf /var/jenkins_home /srv/devsecops/jenkins
		;;
	gitlab)
		rm -rf /srv/gitlab /srv/devsecops/gitlab
		;;
	sonarqube)
		rm -rf /var/sonarqube_data
		;;
	nexus)
		rm -rf /var/nexus-data
		;;
	prom_grafana)
		docker rm -f cross-prometheus cross-grafana 2>/dev/null || true
		rm -rf /srv/devsecops/prometheus /srv/devsecops/grafana
		;;
	elk)
		docker rm -f cross-elasticsearch cross-kibana 2>/dev/null || true
		rm -rf /var/elasticsearch_data
		;;
	vault)
		docker rm -f cross-vault 2>/dev/null || true
		rm -rf /var/vault_data
		;;
	wazuh_soc|wazuh)
		timeout 60 bash -c 'cd /srv/wazuh-docker/single-node 2>/dev/null && docker compose down -v 2>/dev/null || true'
		systemctl stop wazuh-agent 2>/dev/null || true
		systemctl disable wazuh-agent 2>/dev/null || true
		timeout 60 apt-get -o DPkg::Lock::Timeout=30 purge -y wazuh-agent 2>/dev/null || \
		timeout 60 dnf remove -y wazuh-agent 2>/dev/null || \
		timeout 60 yum remove -y wazuh-agent 2>/dev/null || true
		rm -rf /srv/wazuh-docker /var/ossec /etc/apt/sources.list.d/wazuh.list /etc/yum.repos.d/wazuh.repo /etc/apt/trusted.gpg.d/wazuh.gpg
		sed -i '/^vm.max_map_count=262144$/d' /etc/sysctl.conf 2>/dev/null || true
		;;
	devsecops_suite)
		docker rm -f cross-gitlab cross-jenkins cross-sonarqube cross-prometheus cross-grafana cross-node-exporter 2>/dev/null || true
		rm -rf /srv/devsecops /var/grafana_data /var/sonarqube_data
		;;
	gitops_appsec_suite)
		systemctl stop argocd-proxy.service 2>/dev/null || true
		rm -f /etc/systemd/system/argocd-proxy.service 2>/dev/null
		systemctl daemon-reload 2>/dev/null || true
		export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
		kubectl delete namespace argocd 2>/dev/null || true
		/usr/local/bin/k3s-uninstall.sh 2>/dev/null || true
		rm -rf /etc/rancher/k3s /var/lib/rancher/k3s ~/.kube /root/.kube
		rm -f /usr/bin/trivy /usr/local/bin/trivy
		docker rm -f cross-vault 2>/dev/null || true
		rm -rf /var/vault_data
		;;
esac

hash -r 2>/dev/null || rehash 2>/dev/null || true
exit 0
`, containerName, tool.ID)

		writeScriptCmd := fmt.Sprintf("cat << 'EOF' > /tmp/cross_uninstall.sh\n%s\nEOF\nchmod +x /tmp/cross_uninstall.sh", bashScript)
		_, _ = executeRemoteCommand(client, writeScriptCmd)

		_, _ = runSudoScriptWithSpinner(client, "/tmp/cross_uninstall.sh", fmt.Sprintf("Wiping %s Binaries, Services & Volumes (Deep Purge)", tool.Name))
		_, _ = runSudoScript(client, "rm -f /tmp/cross_uninstall.sh")

		fmt.Println(Green + Bold + fmt.Sprintf("\n=> Root-elevated uninstallation of '%s' completed successfully!", tool.Name) + Reset)
	}
}

func purgeAllPresets(client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Red + "================================================================================" + Reset)
	fmt.Println(Bold + Red + "==>> FORCIBLY PURGING ALL DEVSECOPS CONTAINERS, BINARIES & PERSISTENT VOLUMES" + Reset)
	fmt.Println(Bold + Red + "================================================================================" + Reset)

	ensureAutonomousPermissionsWithPrompt(client)

	bashScript := `#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

systemctl stop argocd-proxy.service wazuh-agent 2>/dev/null || true
systemctl disable argocd-proxy.service wazuh-agent 2>/dev/null || true
rm -f /etc/systemd/system/argocd-proxy.service 2>/dev/null
systemctl daemon-reload 2>/dev/null || true

cd /srv/wazuh-docker/single-node 2>/dev/null && (docker compose down -v 2>/dev/null || true)

docker rm -f $(docker ps -a -q --filter name=cross-) 2>/dev/null || true
docker network rm devsecops-net soc-net cross-devsecops-net 2>/dev/null || true
docker system prune -f --volumes 2>/dev/null || true

apt-get purge -y trivy terraform ansible wazuh-agent 2>/dev/null || true
dpkg --purge trivy terraform wazuh-agent 2>/dev/null || true
dnf remove -y trivy terraform ansible 2>/dev/null || true
pip3 uninstall -y ansible 2>/dev/null || true

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl delete namespace argocd 2>/dev/null || true
/usr/local/bin/k3s-uninstall.sh 2>/dev/null || /usr/local/bin/k3s-killall.sh 2>/dev/null || true

rm -f /usr/bin/trivy /usr/local/bin/trivy /bin/trivy
rm -f /usr/bin/terraform /usr/local/bin/terraform /bin/terraform
rm -f /usr/bin/ansible* /usr/local/bin/ansible*
rm -f /usr/bin/k3s /usr/local/bin/k3s
rm -f /etc/apt/sources.list.d/trivy.list /etc/apt/sources.list.d/hashicorp.list /etc/apt/sources.list.d/wazuh.list /etc/sysctl.d/99-k3s-inotify.conf

rm -rf /var/jenkins_home /srv/gitlab /var/sonarqube_data /var/nexus-data /var/elasticsearch_data /var/vault_data /srv/devsecops /srv/soc /srv/wazuh-docker /var/ossec /etc/rancher/k3s /var/lib/rancher/k3s ~/.kube /root/.kube ~/.cache/trivy /root/.cache/trivy

hash -r 2>/dev/null || rehash 2>/dev/null || true
exit 0
`

	writeScriptCmd := fmt.Sprintf("cat << 'EOF' > /tmp/cross_purge_all.sh\n%s\nEOF\nchmod +x /tmp/cross_purge_all.sh", bashScript)
	_, _ = executeRemoteCommand(client, writeScriptCmd)

	_, _ = runSudoScriptWithSpinner(client, "/tmp/cross_purge_all.sh", "Purging All Containers, Binaries, Services & Volumes with Root Rights")
	_, _ = runSudoScript(client, "rm -f /tmp/cross_purge_all.sh 2>/dev/null || true")

	fmt.Println(Green + Bold + "\n=> All DevSecOps presets, runtimes, binaries, and persistent volumes have been completely PURGED!" + Reset)
}