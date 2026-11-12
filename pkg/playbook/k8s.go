package playbook

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	kindClusterName = "cross-k8s-cluster"
	kindContext     = "kind-" + kindClusterName
	minikubeProfile = "minikube"
	kindConfigPath  = "/tmp/cross-kind-config.yaml"
	k8sHeavyTimeout = 30 * time.Minute

	// Fixed token that the GitLab presets seed. If it is not valid on the target,
	// a short-lived token is generated through gitlab-rails and revoked afterwards.
	gitlabSeedToken = "glpat-AdminRootSecretToken123"
	gitlabCIVarName = "KUBECONFIG_BASE64"
	kubeconfigMark  = "# managed-by: cross-ssh"
)

const (
	ingressNginxManifest  = "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.0/deploy/static/provider/kind/deploy.yaml"
	metricsServerManifest = "https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml"
	dashboardManifest     = "https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml"
	metallbManifest       = "https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml"
	certManagerManifest   = "https://github.com/cert-manager/cert-manager/releases/download/v1.14.4/cert-manager.yaml"
	localPathManifest     = "https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy/local-path-storage.yaml"
)

var kindKC = "kubectl --context " + kindContext

// AddonItem tracks interactive checkbox state and active status
type AddonItem struct {
	ID          string
	Name        string
	Description string
	Active      bool
}

// ============================================================================
// GENERIC HELPERS
// ============================================================================

func k8sQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func k8sLastLine(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t != "" && !strings.Contains(t, "[sudo]") {
			return t
		}
	}
	return ""
}

func k8sTail(out string, n int) string {
	var kept []string
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		t := strings.TrimRight(l, " \t")
		if strings.TrimSpace(t) == "" || strings.Contains(t, "[sudo] password") {
			continue
		}
		kept = append(kept, t)
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return strings.Join(kept, "\n")
}

func k8sConfirm(prompt string, def bool) bool {
	ans := strings.ToLower(strings.TrimSpace(transfer.ReadRealtimeInput(prompt)))
	if ans == "" {
		return def
	}
	return ans == "y" || ans == "yes"
}

// k8sReport prints an honest result line and returns whether the step succeeded.
func k8sReport(err error, out, okMsg, failMsg string) bool {
	if err != nil {
		fmt.Println(Red + Bold + "[!] " + failMsg + Reset)
		if t := k8sTail(out, 12); t != "" {
			fmt.Println(Yellow + t + Reset)
		}
		fmt.Printf(Red+"    (%v)\n"+Reset, err)
		return false
	}
	fmt.Println(Green + Bold + "=> " + okMsg + Reset)
	return true
}

// ----------------------------------------------------------------------------
// Target user resolution
//
// runSudoScript executes everything as root, but Minikube/KinD/kubectl keep their
// state in the *login user's* home (~/.minikube, ~/.kube). Running them as root
// looked at a different, empty state - which is why delete/purge/sync did nothing.
// Every cluster command below is therefore executed as the SSH login user.
// ----------------------------------------------------------------------------

type k8sIdentity struct {
	client *ssh.Client
	user   string
	home   string
}

var k8sIdentityCache k8sIdentity
var k8sUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]*\$?$`)

func k8sUser(client *ssh.Client) (string, string) {
	if k8sIdentityCache.client == client && k8sIdentityCache.user != "" {
		return k8sIdentityCache.user, k8sIdentityCache.home
	}
	out, _ := executeRemoteCommand(client, "id -un")
	user := k8sLastLine(out)
	if !k8sUserRe.MatchString(user) {
		user = "root"
	}
	homeOut, _ := executeRemoteCommand(client, "getent passwd "+k8sQuote(user)+" | cut -d: -f6")
	home := k8sLastLine(homeOut)
	if home == "" || !strings.HasPrefix(home, "/") {
		if user == "root" {
			home = "/root"
		} else {
			home = "/home/" + user
		}
	}
	k8sIdentityCache = k8sIdentity{client: client, user: user, home: home}
	return user, home
}

// asK8sUser wraps a script so that it runs as the login user with a pinned HOME/KUBECONFIG.
// It is meant to be embedded inside a root script (runSudoScript*).
func asK8sUser(user, home, inner string) string {
	if user == "root" {
		return "export HOME=" + k8sQuote(home) + " KUBECONFIG=" + k8sQuote(home+"/.kube/config") + "\n" + inner
	}
	return fmt.Sprintf(`sudo -H -u %s env "PATH=$PATH:/usr/local/bin" %s bash -c %s`,
		k8sQuote(user), k8sQuote("KUBECONFIG="+home+"/.kube/config"), k8sQuote(inner))
}

const k8sDockerSockFix = "chmod 666 /var/run/docker.sock 2>/dev/null || true\n"

func runK8s(client *ssh.Client, inner, label string, timeout time.Duration) (string, error) {
	user, home := k8sUser(client)
	return runSudoScriptWithSpinnerTimeout(client, k8sDockerSockFix+asK8sUser(user, home, inner), label, timeout)
}

func runK8sQuiet(client *ssh.Client, inner string) (string, error) {
	user, home := k8sUser(client)
	return runSudoScript(client, k8sDockerSockFix+asK8sUser(user, home, inner))
}

func writeRemoteFile(client *ssh.Client, path, content, mode string) error {
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	_, err := runSudoScript(client, fmt.Sprintf("echo '%s' | base64 -d > %s && chmod %s %s", b64, k8sQuote(path), mode, k8sQuote(path)))
	return err
}

// ----------------------------------------------------------------------------
// Live state detection
// ----------------------------------------------------------------------------

func k8sHasBinary(client *ssh.Client, name string) bool {
	_, err := runSudoScript(client, "command -v "+name+" >/dev/null 2>&1")
	return err == nil
}

func isMinikubeRunning(client *ssh.Client) bool {
	out, _ := runK8sQuiet(client, "minikube status -p "+minikubeProfile+" --format '{{.Host}}/{{.APIServer}}' 2>/dev/null")
	return strings.Contains(out, "Running/Running")
}

func minikubeClusterExists(client *ssh.Client) bool {
	_, err := runSudoScript(client, "docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "+minikubeProfile)
	return err == nil
}

func kindClusterExists(client *ssh.Client) bool {
	_, err := runSudoScript(client, "[ -n \"$(docker ps -aq --filter label=io.x-k8s.kind.cluster="+kindClusterName+" 2>/dev/null)\" ]")
	return err == nil
}

func isKindRunning(client *ssh.Client) bool {
	_, err := runSudoScript(client, "docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "+kindClusterName+"-control-plane")
	return err == nil
}

// k8sActiveContext returns the kubectl context of the live cluster ("" if none).
func k8sActiveContext(client *ssh.Client) string {
	if isKindRunning(client) {
		return kindContext
	}
	if isMinikubeRunning(client) {
		return minikubeProfile
	}
	return ""
}

// ============================================================================
// RAW KEY INPUT
// ============================================================================

// readRawKey captures individual keypresses and ANSI escape sequences
func readRawKey() (string, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		var buf [1]byte
		n, err := os.Stdin.Read(buf[:])
		if err != nil || n == 0 {
			return "", err
		}
		return strings.ToUpper(string(buf[0])), nil
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var buf [3]byte
	numRead, err := os.Stdin.Read(buf[:])
	if err != nil {
		return "", err
	}

	if numRead == 3 && buf[0] == 27 && buf[1] == 91 {
		switch buf[2] {
		case 65:
			return "UP", nil
		case 66:
			return "DOWN", nil
		case 67:
			return "RIGHT", nil
		case 68:
			return "LEFT", nil
		}
	}

	if numRead == 1 {
		switch buf[0] {
		case 13, 10:
			return "ENTER", nil
		case 27:
			return "ESC", nil
		case 32:
			return "SPACE", nil
		case 3:
			return "CTRL_C", nil
		default:
			return strings.ToUpper(string(buf[0])), nil
		}
	}

	return "", nil
}

// ============================================================================
// MAIN MENU
// ============================================================================

// ShowKubernetesMenu provides complete lifecycle management for Minikube and KinD engines
func ShowKubernetesMenu(reader *bufio.Reader, client *ssh.Client) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + "==>> HUB 4: ZERO-TOUCH KUBERNETES LIFECYCLE & PIPELINE PROVISIONER" + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println("  [1] => Install CLI Binaries (Standalone: Select kubectl, Minikube, or KinD)")
		fmt.Println("  [2] => Deploy / Start Minikube Cluster (Single-Node + Docker Driver)")
		fmt.Println("  [3] => Deploy / Start KinD Cluster (Multi-Node: 1 Control + 2 Workers)")
		fmt.Println(Green + Bold + "  [4] => Interactive Live Add-on Manager (Arrow-Key Browse & Apply/Purge)" + Reset)
		fmt.Println("  [5] => Stop Active Clusters (Gracefully Pause Containers to Free Memory)")
		fmt.Println("  [6] => Extract & Auto-Sync Kubeconfig to GitLab CI/CD Variables")
		fmt.Println(Yellow + "  [7] => Delete Clusters (Reset Cluster State without removing binaries)" + Reset)
		fmt.Println(Red + "  [8] => Deep Uninstall & Purge (Select Minikube, KinD, or Complete Wipe)" + Reset)
		fmt.Println(Red + "  [0] => Return to DevSecOps Main Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select Option [0-8]: ")

		switch strings.TrimSpace(choice) {
		case "1":
			promptInstallBinaries(reader, client)
			pauseK8sPrompt(reader)
		case "2":
			DeployZeroTouchKubernetes(client, "minikube")
			pauseK8sPrompt(reader)
		case "3":
			DeployZeroTouchKubernetes(client, "kind")
			pauseK8sPrompt(reader)
		case "4":
			promptSelectClusterAddons(reader, client)
			pauseK8sPrompt(reader)
		case "5":
			stopActiveClusters(client)
			pauseK8sPrompt(reader)
		case "6":
			extractAndDisplayKubeconfig(client)
			pauseK8sPrompt(reader)
		case "7":
			deleteActiveClustersPrompt(reader, client)
			pauseK8sPrompt(reader)
		case "8":
			uninstallKubernetesSuitePrompt(reader, client)
			pauseK8sPrompt(reader)
		case "0", "q", "Q":
			return
		default:
			fmt.Println(Red + "[!] Invalid selection. Please choose 0-8." + Reset)
			time.Sleep(1 * time.Second)
		}
	}
}

func pauseAddonPrompt() {
	fmt.Println(Cyan + "\n--------------------------------------------------------------------------------" + Reset)
	_ = transfer.ReadRealtimeInput(Bold + Yellow + "[ Press ENTER to return to Live Add-on Manager ] " + Reset)
}

func pauseK8sPrompt(reader *bufio.Reader) {
	fmt.Println(Blue + "\n--------------------------------------------------------------------------------" + Reset)
	fmt.Print(Bold + Yellow + "[ Press ENTER to return to Kubernetes Menu ] " + Reset)
	_, _ = reader.ReadString('\n')
}

// ============================================================================
// ADD-ON MANAGERS
// ============================================================================

// promptSelectClusterAddons detects the live cluster and routes to the right manager
func promptSelectClusterAddons(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Println(Bold + Cyan + "==>> AUTONOMOUS KUBERNETES ENGINE DETECTION & IDEMPOTENCY GUARD" + Reset)
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)

	isMinikubeActive := isMinikubeRunning(client)
	isKindActive := isKindRunning(client)

	if !isMinikubeActive && !isKindActive {
		fmt.Println(Red + Bold + "\n[!] IDEMPOTENCY BLOCK: No active Kubernetes cluster is currently running!" + Reset)
		fmt.Println(Yellow + "    => Cannot manage add-ons for a non-existent cluster." + Reset)
		fmt.Println(Yellow + "    => Please deploy Minikube (Option 2) or KinD (Option 3) first." + Reset)
		return
	}

	if isMinikubeActive && !isKindActive {
		fmt.Println(Green + Bold + "=> LIVE CLUSTER DETECTED: Active Minikube Single-Node Cluster" + Reset)
		ShowMinikubeAddonManager(client)
		return
	}

	if isKindActive && !isMinikubeActive {
		fmt.Println(Green + Bold + "=> LIVE CLUSTER DETECTED: Active KinD Multi-Node Cluster (" + kindClusterName + ")" + Reset)
		ShowKindAddonManager(client)
		return
	}

	fmt.Println(Yellow + Bold + "\n[!] CONFLICT DETECTED: Both Minikube and KinD clusters are active simultaneously!" + Reset)
	fmt.Println("  [1] => Manage Minikube Add-ons (Strictly targets Minikube)")
	fmt.Println("  [2] => Manage KinD Add-ons (Strictly targets KinD)")
	fmt.Println(Red + "  [0] => Cancel / Back" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	switch strings.TrimSpace(transfer.ReadRealtimeInput("Select cluster to target [1-2]: ")) {
	case "1":
		ShowMinikubeAddonManager(client)
	case "2":
		ShowKindAddonManager(client)
	}
}

func minikubeAddonSet(client *ssh.Client, id string, enable bool) (string, error) {
	verb, label := "disable", "Disabling"
	if enable {
		verb, label = "enable", "Enabling"
	}
	return runK8s(client, fmt.Sprintf("minikube addons %s %s -p %s 2>&1", verb, id, minikubeProfile),
		fmt.Sprintf("%s Minikube Add-on: %s", label, id), 15*time.Minute)
}

// ShowMinikubeAddonManager provides live arrow-key management for Minikube
func ShowMinikubeAddonManager(client *ssh.Client) {
	addons := []AddonItem{
		{ID: "ingress", Name: "ingress", Description: "NGINX Ingress Controller for HTTP/HTTPS Routing"},
		{ID: "metrics-server", Name: "metrics-server", Description: "Resource Metrics API for kubectl top & HPA"},
		{ID: "dashboard", Name: "dashboard", Description: "Official Web-based Kubernetes UI Portal"},
		{ID: "metallb", Name: "metallb", Description: "Bare-metal LoadBalancer provider for services"},
		{ID: "registry", Name: "registry", Description: "Private Container Image Registry inside cluster"},
		{ID: "storage-provisioner", Name: "storage-provisioner", Description: "Dynamic Local Storage Class Provisioner"},
		{ID: "csi-hostpath-driver", Name: "csi-hostpath-driver", Description: "CSI Hostpath driver for PersistentVolumes"},
		{ID: "logviewer", Name: "logviewer", Description: "Web UI to inspect container & pod logs"},
	}

	refreshMinikubeActiveState(client, addons)
	cursorIdx := 0

	for {
		renderAddonMenu("MINIKUBE LIVE DYNAMIC ADD-ON MANAGER", addons, cursorIdx)

		key, err := readRawKey()
		if err != nil || key == "CTRL_C" || key == "ESC" || key == "0" || key == "Q" {
			return
		}

		switch key {
		case "UP", "W", "K":
			if cursorIdx > 0 {
				cursorIdx--
			} else {
				cursorIdx = len(addons) - 1
			}

		case "DOWN", "S", "J":
			if cursorIdx < len(addons)-1 {
				cursorIdx++
			} else {
				cursorIdx = 0
			}

		case "ENTER", "SPACE":
			handleIndividualAddonAction(client, "minikube", &addons[cursorIdx])
			refreshMinikubeActiveState(client, addons)

		case "A":
			fmt.Print("\033[H\033[2J")
			fmt.Println(Cyan + Bold + "\n=> [1-CLICK ACTION]: Enabling & Applying ALL Minikube Add-ons..." + Reset)
			var failed []string
			for _, item := range addons {
				if _, err := minikubeAddonSet(client, item.ID, true); err != nil {
					failed = append(failed, item.ID)
				}
			}
			refreshMinikubeActiveState(client, addons)
			if len(failed) == 0 {
				fmt.Println(Green + Bold + "=> All Minikube Add-ons enabled successfully!" + Reset)
			} else {
				fmt.Println(Yellow + Bold + "=> Finished with failures: " + strings.Join(failed, ", ") + Reset)
			}
			pauseAddonPrompt()

		case "P":
			fmt.Print("\033[H\033[2J")
			fmt.Println(Red + Bold + "\n=> [1-CLICK ACTION]: Purging & Disabling ALL Minikube Add-ons..." + Reset)
			var failed []string
			for _, item := range addons {
				if item.Active {
					if _, err := minikubeAddonSet(client, item.ID, false); err != nil {
						failed = append(failed, item.ID)
					}
				}
			}
			refreshMinikubeActiveState(client, addons)
			if len(failed) == 0 {
				fmt.Println(Green + Bold + "=> All Minikube Add-ons purged and disabled cleanly!" + Reset)
			} else {
				fmt.Println(Yellow + Bold + "=> Finished with failures: " + strings.Join(failed, ", ") + Reset)
			}
			pauseAddonPrompt()
		}
	}
}

// ShowKindAddonManager provides live arrow-key management for KinD
func ShowKindAddonManager(client *ssh.Client) {
	addons := []AddonItem{
		{ID: "ingress-nginx", Name: "ingress-nginx", Description: "NGINX Ingress Controller (Ports 8085/8443)"},
		{ID: "metrics-server", Name: "metrics-server", Description: "Metrics Server with --kubelet-insecure-tls"},
		{ID: "k8s-dashboard", Name: "k8s-dashboard", Description: "Kubernetes Web Dashboard v2.7.0 UI"},
		{ID: "metallb", Name: "metallb", Description: "MetalLB Layer-2 Load Balancer (auto IP pool)"},
		{ID: "cert-manager", Name: "cert-manager", Description: "Cloud-Native TLS Certificate Automation"},
		{ID: "local-path-storage", Name: "local-path-storage", Description: "Rancher Local Path Provisioner for PVCs"},
	}

	refreshKindActiveState(client, addons)
	cursorIdx := 0

	for {
		renderAddonMenu("KIND LIVE DYNAMIC ADD-ON MANAGER", addons, cursorIdx)

		key, err := readRawKey()
		if err != nil || key == "CTRL_C" || key == "ESC" || key == "0" || key == "Q" {
			return
		}

		switch key {
		case "UP", "W", "K":
			if cursorIdx > 0 {
				cursorIdx--
			} else {
				cursorIdx = len(addons) - 1
			}

		case "DOWN", "S", "J":
			if cursorIdx < len(addons)-1 {
				cursorIdx++
			} else {
				cursorIdx = 0
			}

		case "ENTER", "SPACE":
			handleIndividualAddonAction(client, "kind", &addons[cursorIdx])
			refreshKindActiveState(client, addons)

		case "A":
			fmt.Print("\033[H\033[2J")
			fmt.Println(Cyan + Bold + "\n=> [1-CLICK ACTION]: Deploying ALL KinD Manifest Add-ons..." + Reset)
			var failed []string
			for _, item := range addons {
				if item.Active {
					continue
				}
				if err := applyKindManifest(client, item.ID); err != nil {
					failed = append(failed, item.ID)
				}
			}
			refreshKindActiveState(client, addons)
			if len(failed) == 0 {
				fmt.Println(Green + Bold + "=> All KinD Add-ons deployed successfully!" + Reset)
			} else {
				fmt.Println(Yellow + Bold + "=> Finished with failures: " + strings.Join(failed, ", ") + Reset)
			}
			pauseAddonPrompt()

		case "P":
			fmt.Print("\033[H\033[2J")
			fmt.Println(Red + Bold + "\n=> [1-CLICK ACTION]: Purging ALL KinD Add-on Resources..." + Reset)
			var failed []string
			for _, item := range addons {
				if !item.Active {
					continue
				}
				if item.ID == "local-path-storage" {
					continue // default StorageClass of KinD - removing it breaks PVCs; remove it explicitly via [ENTER]
				}
				if err := purgeKindManifest(client, item.ID); err != nil {
					failed = append(failed, item.ID)
				}
			}
			refreshKindActiveState(client, addons)
			if len(failed) == 0 {
				fmt.Println(Green + Bold + "=> All KinD Add-on resources purged cleanly! (local-path-storage kept: KinD default StorageClass)" + Reset)
			} else {
				fmt.Println(Yellow + Bold + "=> Finished with failures: " + strings.Join(failed, ", ") + Reset)
			}
			pauseAddonPrompt()
		}
	}
}

// renderAddonMenu outputs the live visual terminal dashboard
func renderAddonMenu(title string, addons []AddonItem, cursorIdx int) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Printf(Bold+Cyan+"==>> %s\n"+Reset, title)
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Println(Yellow + "Controls: [↑/↓ Arrow Keys] Navigate | [ENTER] Choose (Apply/Deny) | [0/ESC] Back" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	for idx, item := range addons {
		status := Red + "[ DISABLED ]" + Reset
		if item.Active {
			status = Green + Bold + "[ ACTIVE   ]" + Reset
		}

		if idx == cursorIdx {
			fmt.Printf(Cyan+Bold+" => %s %-20s : %s\n"+Reset, status, item.Name, item.Description)
		} else {
			fmt.Printf("    %s %-20s : %s\n", status, item.Name, item.Description)
		}
	}

	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println(Green + Bold + "  [A] => 1-Click Install / Apply ALL Add-ons" + Reset)
	fmt.Println(Red + Bold + "  [P] => 1-Click Purge / Disable ALL Active Add-ons" + Reset)
	fmt.Println(Yellow + "  [0] => Return to DevSecOps Kubernetes Menu" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
}

// handleIndividualAddonAction presents the Apply/Deny sub-dialog and reports the REAL result
func handleIndividualAddonAction(client *ssh.Client, engine string, item *AddonItem) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Printf(Bold+Cyan+"==>> CONFIGURE ADD-ON: %s (%s)\n"+Reset, strings.ToUpper(item.Name), strings.ToUpper(engine))
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Printf("Description: %s\n", item.Description)
	if item.Active {
		fmt.Printf("Current State: %sActive / Running%s\n\n", Green+Bold, Reset)
	} else {
		fmt.Printf("Current State: %sDisabled / Not Installed%s\n\n", Red+Bold, Reset)
	}

	fmt.Println(Green + Bold + "  [1] => APPLY  (Enable & Provision this Add-on)" + Reset)
	fmt.Println(Red + Bold + "  [2] => DENY   (Disable, Purge & Clean this Add-on)" + Reset)
	fmt.Println(Yellow + "  [0] => CANCEL (Back to list without changing state)" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	clean := strings.TrimSpace(transfer.ReadRealtimeInput("Select action [1=Apply, 2=Deny, 0=Cancel]: "))

	switch clean {
	case "1":
		var out string
		var err error
		if engine == "minikube" {
			out, err = minikubeAddonSet(client, item.ID, true)
		} else {
			err = applyKindManifest(client, item.ID)
		}
		k8sReport(err, out, fmt.Sprintf("Add-on '%s' has been APPLIED successfully!", item.Name),
			fmt.Sprintf("Add-on '%s' failed to apply.", item.Name))
		pauseAddonPrompt()
	case "2":
		var out string
		var err error
		if engine == "minikube" {
			out, err = minikubeAddonSet(client, item.ID, false)
		} else {
			err = purgeKindManifest(client, item.ID)
		}
		k8sReport(err, out, fmt.Sprintf("Add-on '%s' has been PURGED cleanly!", item.Name),
			fmt.Sprintf("Add-on '%s' failed to purge.", item.Name))
		pauseAddonPrompt()
	}
}

// refreshMinikubeActiveState reads the per-addon status from `minikube addons list -o json`
func refreshMinikubeActiveState(client *ssh.Client, addons []AddonItem) {
	out, _ := runK8sQuiet(client, "minikube addons list -p "+minikubeProfile+" -o json 2>/dev/null")
	for i := range addons {
		addons[i].Active = false
	}
	start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
	if start < 0 || end <= start {
		return
	}
	var parsed map[string]struct {
		Status string `json:"Status"`
	}
	if json.Unmarshal([]byte(out[start:end+1]), &parsed) != nil {
		return
	}
	for i := range addons {
		addons[i].Active = strings.EqualFold(parsed[addons[i].ID].Status, "enabled")
	}
}

// refreshKindActiveState queries namespaces / deployments on the KinD context
func refreshKindActiveState(client *ssh.Client, addons []AddonItem) {
	out, _ := runK8sQuiet(client, kindKC+" get ns -o name 2>/dev/null; "+kindKC+" -n kube-system get deploy -o name 2>/dev/null")
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		seen[strings.TrimSpace(l)] = true
	}
	for i := range addons {
		switch addons[i].ID {
		case "ingress-nginx":
			addons[i].Active = seen["namespace/ingress-nginx"]
		case "k8s-dashboard":
			addons[i].Active = seen["namespace/kubernetes-dashboard"]
		case "metallb":
			addons[i].Active = seen["namespace/metallb-system"]
		case "cert-manager":
			addons[i].Active = seen["namespace/cert-manager"]
		case "local-path-storage":
			addons[i].Active = seen["namespace/local-path-storage"]
		case "metrics-server":
			addons[i].Active = seen["deployment.apps/metrics-server"]
		default:
			addons[i].Active = false
		}
	}
}

// applyKindManifest installs a KinD add-on, waits for readiness and returns the real result.
func applyKindManifest(client *ssh.Client, id string) error {
	var inner, label string
	switch id {
	case "ingress-nginx":
		label = "Applying NGINX Ingress Controller"
		inner = kindKC + " apply -f " + ingressNginxManifest + " 2>&1 && " +
			kindKC + " -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=240s 2>&1"
	case "metrics-server":
		label = "Applying Metrics Server (+ --kubelet-insecure-tls)"
		inner = kindKC + " apply -f " + metricsServerManifest + " 2>&1 && " +
			"if ! " + kindKC + " -n kube-system get deploy metrics-server -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -q kubelet-insecure-tls; then " +
			kindKC + ` -n kube-system patch deployment metrics-server --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]' 2>&1; fi && ` +
			kindKC + " -n kube-system rollout status deployment/metrics-server --timeout=180s 2>&1"
	case "k8s-dashboard":
		label = "Applying Kubernetes Dashboard"
		inner = kindKC + " apply -f " + dashboardManifest + " 2>&1 && " +
			kindKC + " -n kubernetes-dashboard rollout status deployment/kubernetes-dashboard --timeout=180s 2>&1"
	case "metallb":
		label = "Applying MetalLB + auto IP pool"
		inner = kindKC + " apply -f " + metallbManifest + " 2>&1 && " +
			kindKC + " -n metallb-system rollout status deployment/controller --timeout=180s 2>&1 && " +
			metallbPoolScript()
	case "cert-manager":
		label = "Applying Cert-Manager"
		inner = kindKC + " apply -f " + certManagerManifest + " 2>&1 && " +
			kindKC + " -n cert-manager rollout status deployment/cert-manager-webhook --timeout=180s 2>&1"
	case "local-path-storage":
		label = "Applying Local Path Provisioner"
		inner = kindKC + " apply -f " + localPathManifest + " 2>&1 && " +
			kindKC + " -n local-path-storage rollout status deployment/local-path-provisioner --timeout=120s 2>&1"
	default:
		return fmt.Errorf("unknown KinD add-on %q", id)
	}

	out, err := runK8s(client, inner, label, 15*time.Minute)
	if err != nil {
		fmt.Println(Red + "[!] " + label + " failed:" + Reset)
		if t := k8sTail(out, 10); t != "" {
			fmt.Println(Yellow + t + Reset)
		}
	}
	return err
}

// metallbPoolScript derives a free address range from the docker "kind" network and applies it.
func metallbPoolScript() string {
	return `{
SUBNET=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.' | head -n1)
[ -n "$SUBNET" ] || { echo "kind docker network not found"; exit 1; }
BASE=$(echo "$SUBNET" | cut -d. -f1-2)
POOL=$(mktemp)
cat > "$POOL" <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: cross-pool
  namespace: metallb-system
spec:
  addresses:
  - ${BASE}.255.200-${BASE}.255.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: cross-l2
  namespace: metallb-system
spec:
  ipAddressPools:
  - cross-pool
EOF
OK=1
for i in 1 2 3 4 5 6 7 8 9 10; do
  if ` + kindKC + ` apply -f "$POOL" >/dev/null 2>&1; then OK=0; break; fi
  sleep 3
done
rm -f "$POOL"
exit $OK
}`
}

// purgeKindManifest removes a KinD add-on completely (CRDs, webhooks, namespaces).
func purgeKindManifest(client *ssh.Client, id string) error {
	urls := map[string]string{
		"ingress-nginx":      ingressNginxManifest,
		"metrics-server":     metricsServerManifest,
		"k8s-dashboard":      dashboardManifest,
		"metallb":            metallbManifest,
		"cert-manager":       certManagerManifest,
		"local-path-storage": localPathManifest,
	}
	url, ok := urls[id]
	if !ok {
		return fmt.Errorf("unknown KinD add-on %q", id)
	}
	label := "Purging " + id
	inner := kindKC + " delete -f " + url + " --ignore-not-found --timeout=180s 2>&1"
	if id == "metallb" {
		inner = kindKC + " -n metallb-system delete ipaddresspool,l2advertisement --all --ignore-not-found 2>&1 || true; " + inner
	}
	out, err := runK8s(client, inner, label, 10*time.Minute)
	if err != nil {
		fmt.Println(Red + "[!] " + label + " failed:" + Reset)
		if t := k8sTail(out, 10); t != "" {
			fmt.Println(Yellow + t + Reset)
		}
	}
	return err
}

// ============================================================================
// BINARY INSTALLERS (verified)
// ============================================================================

const k8sDownloadFn = `
dl() {
	curl -fsSL --retry 3 --max-time 900 -H "User-Agent: Mozilla/5.0" "$1" -o "$2" 2>/dev/null || \
	wget -q -U "Mozilla/5.0" -T 60 -O "$2" "$1" 2>/dev/null
}
install_bin() {
	if [ -s "$1" ] && [ "$(stat -c%s "$1")" -gt 1000000 ]; then
		mv -f "$1" "$2" && chmod 755 "$2" && return 0
	fi
	rm -f "$1"
	return 1
}
ARCH=$(uname -m)
case "$ARCH" in
	aarch64|arm64) A="arm64" ;;
	*)             A="amd64" ;;
esac
mkdir -p /usr/local/bin
`

func k8sVerifyBinary(client *ssh.Client, name string) bool {
	verFlag := "version"
	if name == "kubectl" {
		verFlag = "version --client"
	}
	out, err := runSudoScript(client, fmt.Sprintf("test -x /usr/local/bin/%s && /usr/local/bin/%s %s 2>&1 | head -n 2", name, name, verFlag))
	if err != nil {
		fmt.Println(Red + Bold + "[!] " + name + " was NOT installed (download failed or blocked). Check network/DNS/proxy on the target." + Reset)
		return false
	}
	fmt.Println(Green + Bold + "=> " + name + " installed: " + strings.ReplaceAll(k8sTail(out, 1), "\n", " ") + Reset)
	return true
}

func installKubectlBinary(client *ssh.Client) bool {
	script := k8sDownloadFn + `
K_VER=$(curl -fsSL --max-time 20 https://dl.k8s.io/release/stable.txt 2>/dev/null)
[ -z "$K_VER" ] && K_VER="v1.29.2"
dl "https://dl.k8s.io/release/${K_VER}/bin/linux/${A}/kubectl" /tmp/kubectl && install_bin /tmp/kubectl /usr/local/bin/kubectl
exit 0
`
	_, _ = runSudoScriptWithSpinnerTimeout(client, script, "Deploying kubectl CLI binary to /usr/local/bin", 20*time.Minute)
	return k8sVerifyBinary(client, "kubectl")
}

func installMinikubeBinary(client *ssh.Client) bool {
	script := k8sDownloadFn + `
dl "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-${A}" /tmp/minikube && install_bin /tmp/minikube /usr/local/bin/minikube
exit 0
`
	_, _ = runSudoScriptWithSpinnerTimeout(client, script, "Deploying Minikube Engine binary to /usr/local/bin", 20*time.Minute)
	return k8sVerifyBinary(client, "minikube")
}

func installKindBinary(client *ssh.Client) bool {
	script := k8sDownloadFn + `
dl "https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-${A}" /tmp/kind && install_bin /tmp/kind /usr/local/bin/kind
exit 0
`
	_, _ = runSudoScriptWithSpinnerTimeout(client, script, "Deploying KinD Engine binary to /usr/local/bin", 20*time.Minute)
	return k8sVerifyBinary(client, "kind")
}

// promptInstallBinaries allows selective installation of standalone binaries
func promptInstallBinaries(reader *bufio.Reader, client *ssh.Client) {
	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "==>> SELECT KUBERNETES TOOLCHAIN BINARY TO INSTALL / UPGRADE:" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)
	fmt.Println("  [1] => Install kubectl CLI only (/usr/local/bin/kubectl)")
	fmt.Println("  [2] => Install Minikube CLI only (/usr/local/bin/minikube)")
	fmt.Println("  [3] => Install KinD CLI only (/usr/local/bin/kind)")
	fmt.Println("  [4] => Install ALL Binaries (kubectl, Minikube, KinD)")
	fmt.Println(Red + "  [0] => Cancel / Back" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	cleanChoice := strings.TrimSpace(transfer.ReadRealtimeInput("Select binary installer [Default 4]: "))
	if cleanChoice == "" {
		cleanChoice = "4"
	}
	if cleanChoice == "0" {
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	ok := true
	switch cleanChoice {
	case "1":
		ok = installKubectlBinary(client)
	case "2":
		ok = installMinikubeBinary(client)
	case "3":
		ok = installKindBinary(client)
	default:
		a := installKubectlBinary(client)
		b := installMinikubeBinary(client)
		c := installKindBinary(client)
		ok = a && b && c
	}

	if ok {
		fmt.Println(Green + Bold + "\n==>> TARGET KUBERNETES BINARIES INSTALLED SYSTEM-WIDE (/usr/local/bin)!" + Reset)
	} else {
		fmt.Println(Red + Bold + "\n==>> ONE OR MORE BINARIES FAILED TO INSTALL - see messages above." + Reset)
	}
}

// ============================================================================
// CLUSTER DEPLOYMENT
// ============================================================================

func buildKindConfig(targetIP string, expose bool) string {
	var sb strings.Builder
	sb.WriteString("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n")
	if expose {
		sb.WriteString("networking:\n  apiServerAddress: \"0.0.0.0\"\n")
	}
	sb.WriteString("nodes:\n- role: control-plane\n  kubeadmConfigPatches:\n  - |\n    kind: InitConfiguration\n    nodeRegistration:\n      kubeletExtraArgs:\n        node-labels: \"ingress-ready=true\"\n")
	if expose && net.ParseIP(targetIP) != nil {
		sb.WriteString("  - |\n    kind: ClusterConfiguration\n    apiServer:\n      certSANs:\n      - \"" + targetIP + "\"\n")
	}
	sb.WriteString("  extraPortMappings:\n  - containerPort: 80\n    hostPort: 8085\n    protocol: TCP\n  - containerPort: 443\n    hostPort: 8443\n    protocol: TCP\n- role: worker\n- role: worker\n")
	return sb.String()
}

// prepareK8sHome makes sure state directories belong to the login user (older runs may have created them as root)
func prepareK8sHome(client *ssh.Client) {
	user, home := k8sUser(client)
	script := fmt.Sprintf(`
mkdir -p %[1]s/.kube %[1]s/.minikube
if [ %[2]s != root ]; then chown -R %[2]s: %[1]s/.kube %[1]s/.minikube 2>/dev/null || true; fi
chmod 700 %[1]s/.kube 2>/dev/null || true
chmod 666 /var/run/docker.sock 2>/dev/null || true
sysctl -w fs.inotify.max_user_watches=524288 fs.inotify.max_user_instances=8192 >/dev/null 2>&1 || true
exit 0
`, k8sQuote(home), k8sQuote(user))
	_, _ = runSudoScript(client, script)
}

// DeployZeroTouchKubernetes manages conflicting clusters and starts the target engine
func DeployZeroTouchKubernetes(client *ssh.Client, engineChoice string) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Printf(Bold+Cyan+"==>> ZERO-TOUCH KUBERNETES PROVISIONER: %s\n"+Reset, strings.ToUpper(engineChoice))
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)

	if !CheckSpacePreFlight(client, 8192) {
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)
	EnsureContainerEngine(client)
	prepareK8sHome(client)

	if !k8sHasBinary(client, "kubectl") {
		if !installKubectlBinary(client) {
			return
		}
	}

	targetIP := resolveTargetIP(client)

	if strings.ToLower(engineChoice) == "kind" {
		if !k8sHasBinary(client, "kind") {
			if !installKindBinary(client) {
				return
			}
		}
		// Pause (not destroy) Minikube to avoid resource contention
		if k8sHasBinary(client, "minikube") && isMinikubeRunning(client) {
			_, _ = runK8s(client, "minikube stop -p "+minikubeProfile+" 2>&1", "Pausing Minikube to free resources", 10*time.Minute)
		}

		create := true
		if kindClusterExists(client) {
			if isKindRunning(client) {
				fmt.Println(Green + Bold + "=> KinD cluster '" + kindClusterName + "' is already running." + Reset)
				create = k8sConfirm("Recreate it from scratch (DESTROYS all workloads)? [y/N]: ", false)
			} else {
				fmt.Println(Yellow + "=> KinD cluster '" + kindClusterName + "' exists but is stopped." + Reset)
				if k8sConfirm("Recreate from scratch instead of restarting it? [y/N]: ", false) {
					create = true
				} else {
					create = false
					out, err := runSudoScriptWithSpinner(client,
						"docker ps -aq --filter label=io.x-k8s.kind.cluster="+kindClusterName+" | xargs -r docker start",
						"Restarting KinD node containers")
					if !k8sReport(err, out, "KinD nodes restarted.", "Failed to restart KinD nodes.") {
						return
					}
					_, _ = runK8s(client, "kind export kubeconfig --name "+kindClusterName+" 2>&1", "Re-exporting KinD kubeconfig", 2*time.Minute)
				}
			}
			if create {
				if !k8sDeleteKind(client) {
					return
				}
			}
		}

		if create {
			expose := k8sConfirm("Expose KinD API on all interfaces (needed for Docker-based GitLab runners)? [y/N]: ", false)
			if err := writeRemoteFile(client, kindConfigPath, buildKindConfig(targetIP, expose), "644"); err != nil {
				fmt.Println(Red + "[!] Could not write KinD config: " + err.Error() + Reset)
				return
			}
			out, err := runK8s(client,
				"kind create cluster --name "+kindClusterName+" --config "+kindConfigPath+" --wait 180s 2>&1",
				"Deploying KinD Multi-Node Topology over Docker Engine", k8sHeavyTimeout)
			if !k8sReport(err, out, "KinD cluster created.", "KinD cluster creation FAILED.") {
				return
			}
		}

		if !isKindRunning(client) {
			fmt.Println(Red + Bold + "[!] KinD control-plane container is not running after deployment." + Reset)
			return
		}
		if create {
			applyKindAddons(client)
		}
	} else {
		if !k8sHasBinary(client, "minikube") {
			if !installMinikubeBinary(client) {
				return
			}
		}
		// Pause (not destroy) KinD to avoid resource contention
		if kindClusterExists(client) && isKindRunning(client) {
			_, _ = runSudoScriptWithSpinner(client,
				"docker ps -q --filter label=io.x-k8s.kind.cluster="+kindClusterName+" | xargs -r docker stop",
				"Pausing KinD nodes to free resources")
		}

		user, _ := k8sUser(client)
		force := ""
		if user == "root" {
			force = " --force"
		}
		out, err := runK8s(client,
			"OUT=$(minikube start -p "+minikubeProfile+" --driver=docker"+force+" 2>&1); RC=$?; echo \"$OUT\" | tail -n 15; exit $RC",
			"Deploying Minikube Single-Node Cluster over Docker Engine", k8sHeavyTimeout)
		if !k8sReport(err, out, "Minikube started.", "Minikube start FAILED.") {
			return
		}

		for _, a := range []string{"ingress", "metrics-server", "dashboard"} {
			if _, aerr := minikubeAddonSet(client, a, true); aerr != nil {
				fmt.Println(Yellow + "[!] Add-on '" + a + "' could not be enabled (non-fatal)." + Reset)
			}
		}

		if !isMinikubeRunning(client) {
			fmt.Println(Red + Bold + "[!] Minikube reports it is not running after start." + Reset)
			return
		}
	}

	syncKubeconfigPermissions(client)
	nodes, _ := runK8sQuiet(client, "kubectl --context "+k8sActiveContextName(engineChoice)+" get nodes -o wide 2>&1")
	if t := k8sTail(nodes, 6); t != "" {
		fmt.Println(Cyan + t + Reset)
	}
	extractAndDisplayKubeconfig(client)
}

func k8sActiveContextName(engine string) string {
	if strings.ToLower(engine) == "kind" {
		return kindContext
	}
	return minikubeProfile
}

// applyKindAddons offers add-ons right after a fresh KinD cluster is created
func applyKindAddons(client *ssh.Client) {
	fmt.Println(Yellow + Bold + "\n=> KinD Cluster Online! Selecting Gold-Standard Add-ons to Pre-Enable..." + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] => Enable NGINX Ingress Controller (Web Traffic Routing & TLS on Port 8085/8443)")
	fmt.Println("  [2] => Enable Metrics Server (kubectl top nodes/pods & HPA Autoscaling)")
	fmt.Println("  [3] => Enable Kubernetes Web Dashboard (Visual Cluster Portal)")
	fmt.Println("  [4] => Enable ALL Recommended Add-ons (Gold Standard Default)")
	fmt.Println("  [0] => Skip Add-ons")
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	choice := strings.TrimSpace(transfer.ReadRealtimeInput("Select KinD Add-on Deployment [Default 4]: "))
	if choice == "" {
		choice = "4"
	}

	var ids []string
	switch choice {
	case "1":
		ids = []string{"ingress-nginx"}
	case "2":
		ids = []string{"metrics-server"}
	case "3":
		ids = []string{"k8s-dashboard"}
	case "4":
		ids = []string{"ingress-nginx", "metrics-server", "k8s-dashboard"}
	default:
		return
	}
	for _, id := range ids {
		if err := applyKindManifest(client, id); err == nil {
			fmt.Println(Green + Bold + "=> Add-on '" + id + "' deployed successfully!" + Reset)
		}
	}
}

// ============================================================================
// STOP / DELETE
// ============================================================================

// stopActiveClusters gracefully stops both engines without data loss
func stopActiveClusters(client *ssh.Client) {
	ensureAutonomousPermissionsWithPrompt(client)
	stopped := false

	if k8sHasBinary(client, "minikube") && isMinikubeRunning(client) {
		out, err := runK8s(client, "minikube stop -p "+minikubeProfile+" 2>&1", "Pausing Minikube", 10*time.Minute)
		if k8sReport(err, out, "Minikube paused.", "Minikube failed to stop.") {
			stopped = true
		}
	}
	if isKindRunning(client) {
		out, err := runSudoScriptWithSpinner(client,
			"docker ps -q --filter label=io.x-k8s.kind.cluster="+kindClusterName+" | xargs -r docker stop",
			"Pausing KinD node containers")
		if k8sReport(err, out, "KinD nodes paused.", "KinD nodes failed to stop.") {
			stopped = true
		}
	}
	if !stopped {
		fmt.Println(Yellow + "=> No running Minikube or KinD cluster was found - nothing to pause." + Reset)
		return
	}
	fmt.Println(Green + Bold + "=> Active Kubernetes clusters paused to reclaim memory." + Reset)
}

func k8sCleanContexts(client *ssh.Client, names ...string) {
	if !k8sHasBinary(client, "kubectl") {
		return
	}
	var parts []string
	for _, n := range names {
		q := k8sQuote(n)
		parts = append(parts,
			"kubectl config delete-context "+q+" >/dev/null 2>&1",
			"kubectl config delete-cluster "+q+" >/dev/null 2>&1",
			"kubectl config delete-user "+q+" >/dev/null 2>&1")
	}
	_, _ = runK8sQuiet(client, strings.Join(parts, "; ")+"; true")
}

// k8sDeleteMinikube deletes the profile (as the correct user) and verifies it is really gone.
func k8sDeleteMinikube(client *ssh.Client) bool {
	var out string
	if k8sHasBinary(client, "minikube") {
		out, _ = runK8s(client, "minikube delete -p "+minikubeProfile+" 2>&1", "Deleting Minikube cluster", 15*time.Minute)
	}
	// Guaranteed fallback at docker level
	_, _ = runSudoScriptWithSpinner(client,
		"docker rm -f "+minikubeProfile+" >/dev/null 2>&1; docker volume rm -f "+minikubeProfile+" >/dev/null 2>&1; docker network rm "+minikubeProfile+" >/dev/null 2>&1; true",
		"Removing leftover Minikube container, volume & network")
	k8sCleanContexts(client, minikubeProfile)

	if minikubeClusterExists(client) {
		fmt.Println(Red + Bold + "[!] Minikube container is STILL present after delete." + Reset)
		if t := k8sTail(out, 10); t != "" {
			fmt.Println(Yellow + t + Reset)
		}
		return false
	}
	fmt.Println(Green + Bold + "=> Minikube cluster deleted and verified gone." + Reset)
	return true
}

// k8sDeleteKind deletes the KinD cluster and verifies it is really gone.
func k8sDeleteKind(client *ssh.Client) bool {
	var out string
	var err error
	if k8sHasBinary(client, "kind") {
		out, err = runK8s(client, "kind delete cluster --name "+kindClusterName+" 2>&1", "Deleting KinD cluster", 10*time.Minute)
	}
	_, _ = runSudoScriptWithSpinner(client,
		"docker ps -aq --filter label=io.x-k8s.kind.cluster="+kindClusterName+" | xargs -r docker rm -f -v >/dev/null 2>&1; true",
		"Removing leftover KinD node containers")
	k8sCleanContexts(client, kindContext)

	if kindClusterExists(client) {
		fmt.Println(Red + Bold + "[!] KinD node containers are STILL present after delete." + Reset)
		if t := k8sTail(out, 10); t != "" {
			fmt.Println(Yellow + t + Reset)
		}
		return false
	}
	if err != nil {
		fmt.Println(Yellow + "   (kind CLI reported an error, but all node containers were removed via docker.)" + Reset)
	}
	fmt.Println(Green + Bold + "=> KinD cluster deleted and verified gone." + Reset)
	return true
}

// deleteActiveClustersPrompt allows resetting cluster topologies without deleting CLI binaries
func deleteActiveClustersPrompt(reader *bufio.Reader, client *ssh.Client) {
	fmt.Println(Yellow + Bold + "\n================================================================================" + Reset)
	fmt.Println(Yellow + Bold + "==>> SELECT CLUSTER TOPOLOGY TO DELETE (Binaries Will Remain Intact):" + Reset)
	fmt.Println(Yellow + Bold + "================================================================================" + Reset)
	fmt.Println("  [1] => Delete Minikube Cluster only")
	fmt.Println("  [2] => Delete KinD Cluster only (" + kindClusterName + ")")
	fmt.Println("  [3] => Delete BOTH Minikube & KinD Clusters")
	fmt.Println(Red + "  [0] => Cancel" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	ans := strings.TrimSpace(transfer.ReadRealtimeInput("Select cluster to delete [Default 3]: "))
	if ans == "" {
		ans = "3"
	}
	if ans != "1" && ans != "2" && ans != "3" {
		return
	}
	if !k8sConfirm(Red+"This permanently destroys the selected cluster(s) and all workloads. Continue? [y/N]: "+Reset, false) {
		fmt.Println(Yellow + "=> Cancelled." + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	switch ans {
	case "1":
		k8sDeleteMinikube(client)
	case "2":
		k8sDeleteKind(client)
	case "3":
		a := k8sDeleteMinikube(client)
		b := k8sDeleteKind(client)
		if a && b {
			fmt.Println(Green + Bold + "=> Both clusters deleted successfully!" + Reset)
		}
	}
}

// ============================================================================
// DEEP UNINSTALL / PURGE
// ============================================================================

func k8sReportLeftovers(client *ssh.Client, names ...string) {
	for _, n := range names {
		out, err := runSudoScript(client, "command -v "+n)
		if err == nil {
			fmt.Println(Yellow + Bold + "[!] '" + n + "' still resolves to " + k8sLastLine(out) +
				" (probably installed by a package manager - remove it with apt/dnf)." + Reset)
		} else {
			fmt.Println(Green + "   [✔] " + n + " removed." + Reset)
		}
	}
}

func k8sPurgeMinikube(client *ssh.Client) {
	_, home := k8sUser(client)
	k8sDeleteMinikube(client)
	if k8sHasBinary(client, "minikube") {
		_, _ = runK8s(client, "minikube delete --all --purge 2>&1 || true", "Purging all Minikube profiles & cache", 15*time.Minute)
	}
	_, _ = runSudoScriptWithSpinner(client,
		"rm -f /usr/local/bin/minikube /usr/bin/minikube; rm -rf "+k8sQuote(home+"/.minikube")+" /root/.minikube; true",
		"Removing Minikube binary & ~/.minikube cache")
	k8sReportLeftovers(client, "minikube")
}

func k8sPurgeKind(client *ssh.Client) {
	k8sDeleteKind(client)
	_, _ = runSudoScriptWithSpinner(client,
		"rm -f /usr/local/bin/kind /usr/bin/kind "+kindConfigPath+"; true",
		"Removing KinD binary & config")
	k8sReportLeftovers(client, "kind")
}

func k8sPurgeKubectl(client *ssh.Client) {
	_, _ = runSudoScriptWithSpinner(client, "rm -f /usr/local/bin/kubectl /usr/bin/kubectl; true", "Removing kubectl CLI Binary")
	k8sReportLeftovers(client, "kubectl")
}

// uninstallKubernetesSuitePrompt provides selective deep-purge options
func uninstallKubernetesSuitePrompt(reader *bufio.Reader, client *ssh.Client) {
	fmt.Println(Red + Bold + "\n================================================================================" + Reset)
	fmt.Println(Red + Bold + "==>> SELECT ENGINE OR TOOL TO DEEP PURGE & UNINSTALL:" + Reset)
	fmt.Println(Red + Bold + "================================================================================" + Reset)
	fmt.Println("  [1] => Deep Purge Minikube (cluster, ~/.minikube cache, /usr/local/bin/minikube)")
	fmt.Println("  [2] => Deep Purge KinD (" + kindClusterName + " containers, /usr/local/bin/kind)")
	fmt.Println("  [3] => Deep Purge kubectl CLI (/usr/local/bin/kubectl)")
	fmt.Println(Red + "  [4] => DEEP PURGE EVERYTHING (Minikube, KinD, kubectl and their kubeconfig entries)" + Reset)
	fmt.Println(Yellow + "  [0] => Cancel" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	cleanChoice := strings.TrimSpace(transfer.ReadRealtimeInput("Select uninstallation target [0-4]: "))
	if cleanChoice == "0" || cleanChoice == "" {
		fmt.Println(Yellow + "=> Uninstallation cancelled." + Reset)
		return
	}
	if cleanChoice != "1" && cleanChoice != "2" && cleanChoice != "3" && cleanChoice != "4" {
		fmt.Println(Red + "[!] Invalid selection." + Reset)
		return
	}
	if !k8sConfirm(Red+"This is irreversible. Continue? [y/N]: "+Reset, false) {
		fmt.Println(Yellow + "=> Uninstallation cancelled." + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	switch cleanChoice {
	case "1":
		k8sPurgeMinikube(client)
		fmt.Println(Green + Bold + "=> Minikube purge finished." + Reset)
	case "2":
		k8sPurgeKind(client)
		fmt.Println(Green + Bold + "=> KinD purge finished." + Reset)
	case "3":
		k8sPurgeKubectl(client)
		fmt.Println(Green + Bold + "=> kubectl purge finished." + Reset)
	case "4":
		wipeKube := k8sConfirm("Also delete the ENTIRE ~/.kube directory (affects ALL your other clusters)? [y/N]: ", false)
		k8sPurgeMinikube(client)
		k8sPurgeKind(client)
		_, home := k8sUser(client)
		if wipeKube {
			_, _ = runSudoScriptWithSpinner(client,
				"rm -rf "+k8sQuote(home+"/.kube")+" /root/.kube /tmp/active_kube.yaml; true", "Removing ~/.kube")
		}
		k8sPurgeKubectl(client)
		fmt.Println(Green + Bold + "=> Kubernetes toolchain purge finished." + Reset)
		fmt.Println(Cyan + "   (Cluster contexts were removed from kubeconfig; /etc/kubernetes and k3s files were left untouched.)" + Reset)
	}
}

// ============================================================================
// KUBECONFIG EXTRACTION & GITLAB SYNC
// ============================================================================

// getFlatKubeconfig returns a self-contained kubeconfig (certs embedded) for one context.
// Plain `kubectl config view --raw` is NOT enough: Minikube references cert FILES, which are
// useless once the config leaves the host (GitLab CI).
func getFlatKubeconfig(client *ssh.Client, ctx string) (string, error) {
	out, err := runK8sQuiet(client, "kubectl config view --raw --flatten --minify --context "+k8sQuote(ctx)+" 2>&1")
	idx := strings.Index(out, "apiVersion:")
	if err != nil || idx < 0 || !strings.Contains(out, "clusters:") {
		return "", fmt.Errorf("kubectl could not produce a kubeconfig for context %q: %s", ctx, k8sTail(out, 3))
	}
	return strings.TrimSpace(out[idx:]) + "\n", nil
}

var k8sServerLineRe = regexp.MustCompile(`(?m)^([ \t]*)server:[ \t]*https://(127\.0\.0\.1|localhost|0\.0\.0\.0)(:\d+)?[ \t]*$`)

// rewriteKubeconfigServer points a loopback API endpoint to the host IP (SAN trick for KinD certs).
func rewriteKubeconfigServer(cfg, host string) string {
	return k8sServerLineRe.ReplaceAllString(cfg, "${1}server: https://"+host+"${3}\n${1}tls-server-name: kubernetes")
}

// syncKubeconfigPermissions fixes ownership/permissions and mirrors the live kubeconfig for root-run presets.
// It never overwrites a root/k3s kubeconfig it does not own.
func syncKubeconfigPermissions(client *ssh.Client) {
	user, home := k8sUser(client)
	ctx := k8sActiveContext(client)

	if ctx != "" {
		if cfg, err := getFlatKubeconfig(client, ctx); err == nil {
			_ = writeRemoteFile(client, "/tmp/active_kube.yaml", kubeconfigMark+"\n"+cfg, "600")
		}
	}

	script := fmt.Sprintf(`
mkdir -p %[1]s/.kube
if [ %[2]s != root ]; then chown -R %[2]s: %[1]s/.kube 2>/dev/null || true; fi
chmod 700 %[1]s/.kube; chmod 600 %[1]s/.kube/config 2>/dev/null || true
chmod 666 /var/run/docker.sock 2>/dev/null || true

copy_managed() {
	[ -s /tmp/active_kube.yaml ] || return 0
	if [ ! -e "$1" ] || grep -q 'managed-by: cross-ssh' "$1" 2>/dev/null; then
		mkdir -p "$(dirname "$1")"
		cp -f /tmp/active_kube.yaml "$1" && chmod 600 "$1" && echo "SYNCED|$1"
	else
		echo "SKIPPED|$1"
	fi
}
if [ %[2]s != root ]; then copy_managed /root/.kube/config; fi
if ! command -v k3s >/dev/null 2>&1; then copy_managed /etc/rancher/k3s/k3s.yaml; fi
rm -f /tmp/active_kube.yaml
exit 0
`, k8sQuote(home), k8sQuote(user))
	out, _ := runSudoScriptWithSpinner(client, script, "Synchronizing Local Kubeconfig Permissions")
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "SYNCED|") {
			fmt.Println(Cyan + "   => kubeconfig mirrored to " + strings.TrimPrefix(l, "SYNCED|") + Reset)
		} else if strings.HasPrefix(l, "SKIPPED|") {
			fmt.Println(Yellow + "   => left untouched (not managed by this tool): " + strings.TrimPrefix(l, "SKIPPED|") + Reset)
		}
	}
}

// extractAndDisplayKubeconfig extracts a portable kubeconfig and syncs it to GitLab CI/CD variables
func extractAndDisplayKubeconfig(client *ssh.Client) {
	fmt.Println(Cyan + Bold + "\n================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "==>> KUBECONFIG EXTRACTION & GITLAB CI/CD SYNC" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	ensureAutonomousPermissionsWithPrompt(client)

	mk, kd := isMinikubeRunning(client), isKindRunning(client)
	ctx := ""
	switch {
	case mk && kd:
		fmt.Println(Yellow + "Both clusters are running.  [1] KinD   [2] Minikube" + Reset)
		if strings.TrimSpace(transfer.ReadRealtimeInput("Select cluster to export [Default 1]: ")) == "2" {
			ctx = minikubeProfile
		} else {
			ctx = kindContext
		}
	case kd:
		ctx = kindContext
	case mk:
		ctx = minikubeProfile
	default:
		fmt.Println(Red + "[!] No running Minikube/KinD cluster found. Deploy one first (Option 2 or 3)." + Reset)
		return
	}
	fmt.Println(Cyan + "=> Exporting context: " + ctx + Reset)

	cfg, err := getFlatKubeconfig(client, ctx)
	if err != nil {
		fmt.Println(Red + "[!] " + err.Error() + Reset)
		return
	}

	targetIP := resolveTargetIP(client)
	syncKubeconfigPermissions(client)

	if ctx == kindContext && k8sServerLineRe.MatchString(cfg) && net.ParseIP(targetIP) != nil && targetIP != "127.0.0.1" {
		fmt.Println(Yellow + "=> The API endpoint is loopback-only. A GitLab runner in a Docker container cannot reach it." + Reset)
		if k8sConfirm("Rewrite API server to https://"+targetIP+" for the CI copy? (cluster must have been created with API exposure) [y/N]: ", false) {
			cfg = rewriteKubeconfigServer(cfg, targetIP)
		}
	}

	synced := autoInjectGitLabKubeconfigResult(client, cfg)

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> KUBECONFIG EXPORT SUMMARY" + Reset)
	fmt.Println(Cyan + Bold + "   => Context             : " + ctx + Reset)
	fmt.Println(Cyan + Bold + "   => Self-contained cfg  : yes (certs embedded via --flatten)" + Reset)
	if synced {
		fmt.Println(Green + Bold + "   => GitLab CI variable  : " + gitlabCIVarName + " synchronized & verified" + Reset)
	} else {
		fmt.Println(Yellow + Bold + "   => GitLab CI variable  : NOT synchronized (see message above)" + Reset)
	}
	fmt.Println(Yellow + "   => Manual test         : kubectl --context " + ctx + " get nodes -o wide" + Reset)
	if ctx == minikubeProfile {
		fmt.Println(Yellow + "   => Note                : Minikube's API (192.168.49.2) is only reachable from this host; use a shell/host-network runner." + Reset)
	}
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

// autoInjectGitLabKubeconfig is kept for API compatibility with other files.
func autoInjectGitLabKubeconfig(client *ssh.Client, targetIP string, rawKubeconfig string) {
	_ = autoInjectGitLabKubeconfigResult(client, rawKubeconfig)
}

// autoInjectGitLabKubeconfigResult creates/updates the instance-level CI variable and verifies it.
func autoInjectGitLabKubeconfigResult(client *ssh.Client, kubeconfig string) bool {
	running, _ := runSudoScript(client, "docker ps --format '{{.Names}}' 2>/dev/null | grep -x cross-gitlab")
	if !strings.Contains(running, "cross-gitlab") {
		fmt.Println(Yellow + "=> GitLab container 'cross-gitlab' is not running - skipping CI/CD variable sync." + Reset)
		fmt.Println(Yellow + "   Deploy GitLab from the DevSecOps presets first, then run option [6] again." + Reset)
		return false
	}

	port := "8929"
	portsOut, _ := runSudoScript(client, `docker inspect cross-gitlab --format '{{range $p, $c := .HostConfig.PortBindings}}{{$p}}={{(index $c 0).HostPort}}{{"\n"}}{{end}}' 2>/dev/null`)
	for _, l := range strings.Split(portsOut, "\n") {
		l = strings.TrimSpace(l)
		if kv := strings.SplitN(l, "=", 2); len(kv) == 2 && strings.HasSuffix(kv[0], "/tcp") && kv[0] != "22/tcp" {
			if _, err := strconv.Atoi(kv[1]); err == nil {
				port = kv[1]
				break
			}
		}
	}

	b64 := base64.StdEncoding.EncodeToString([]byte(kubeconfig))
	if len(b64) > 9900 {
		fmt.Println(Red + "[!] Encoded kubeconfig is " + strconv.Itoa(len(b64)) + " chars; GitLab CI variables are limited to 10,000. Sync aborted." + Reset)
		return false
	}
	body, _ := json.Marshal(map[string]interface{}{
		"key":           gitlabCIVarName,
		"value":         b64,
		"variable_type": "env_var",
		"protected":     false,
		"masked":        false,
	})
	bodyB64 := base64.StdEncoding.EncodeToString(body)

	script := fmt.Sprintf(`
umask 077
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BASE="http://127.0.0.1:%[1]s"
echo '%[2]s' | base64 -d > "$TMP/body.json"
VAR="%[4]s"

READY=0
for i in $(seq 1 45); do
	C=$(curl -s -o /dev/null -w '%%{http_code}' --max-time 5 "$BASE/users/sign_in" 2>/dev/null)
	if [ "$C" = "200" ] || [ "$C" = "302" ]; then READY=1; break; fi
	sleep 4
done
if [ "$READY" != "1" ]; then echo "GITLAB_NOT_READY"; exit 0; fi

check_token() {
	curl -s -o /dev/null -w '%%{http_code}' --max-time 15 -H "PRIVATE-TOKEN: $1" "$BASE/api/v4/user" 2>/dev/null
}

TOKEN='%[3]s'
GENERATED=0
PAT_ID=""
if [ "$(check_token "$TOKEN")" != "200" ]; then
	RAW=$(docker exec cross-gitlab gitlab-rails runner "u = User.find_by_username('root'); t = u.personal_access_tokens.create!(name: 'cross-k8s-sync-' + Time.now.to_i.to_s, scopes: [:api], expires_at: 1.day.from_now); puts 'PAT_OK|' + t.id.to_s + '|' + t.token" 2>/dev/null | grep '^PAT_OK|' | tail -n1)
	PAT_ID=$(echo "$RAW" | cut -d'|' -f2)
	TOKEN=$(echo "$RAW" | cut -d'|' -f3)
	GENERATED=1
fi
if [ -z "$TOKEN" ] || [ "$(check_token "$TOKEN")" != "200" ]; then echo "AUTH_FAILED"; exit 0; fi

CODE=$(curl -s -o "$TMP/resp" -w '%%{http_code}' --max-time 30 -X POST "$BASE/api/v4/admin/ci/variables" -H "PRIVATE-TOKEN: $TOKEN" -H "Content-Type: application/json" --data @"$TMP/body.json")
ACTION="created"
if [ "$CODE" = "400" ] || [ "$CODE" = "409" ]; then
	CODE=$(curl -s -o "$TMP/resp" -w '%%{http_code}' --max-time 30 -X PUT "$BASE/api/v4/admin/ci/variables/$VAR" -H "PRIVATE-TOKEN: $TOKEN" -H "Content-Type: application/json" --data @"$TMP/body.json")
	ACTION="updated"
fi
VERIFY=$(curl -s -o /dev/null -w '%%{http_code}' --max-time 15 -H "PRIVATE-TOKEN: $TOKEN" "$BASE/api/v4/admin/ci/variables/$VAR")
echo "RESULT|$ACTION|$CODE|$VERIFY"
if [ "$CODE" != "200" ] && [ "$CODE" != "201" ]; then echo "ERR|$(head -c 300 "$TMP/resp")"; fi
if [ "$GENERATED" = "1" ] && [ -n "$PAT_ID" ]; then
	curl -s -o /dev/null -X DELETE --max-time 15 -H "PRIVATE-TOKEN: $TOKEN" "$BASE/api/v4/personal_access_tokens/$PAT_ID"
fi
exit 0
`, port, bodyB64, gitlabSeedToken, gitlabCIVarName)

	out, _ := runSudoScriptWithSpinnerTimeout(client, script, "Syncing kubeconfig to GitLab CI/CD Variables", 15*time.Minute)

	switch {
	case strings.Contains(out, "GITLAB_NOT_READY"):
		fmt.Println(Red + "[!] GitLab did not become ready on port " + port + " (still booting?). Retry in a minute." + Reset)
		return false
	case strings.Contains(out, "AUTH_FAILED"):
		fmt.Println(Red + "[!] Could not authenticate to GitLab (seed token invalid and token generation failed)." + Reset)
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "RESULT|") {
			f := strings.Split(l, "|")
			if len(f) == 4 && (f[2] == "200" || f[2] == "201") && f[3] == "200" {
				fmt.Println(Green + Bold + "=> Pipeline Bridge: " + gitlabCIVarName + " " + f[1] + " in GitLab (instance-level variable, HTTP " + f[2] + ", verified)." + Reset)
				return true
			}
			fmt.Println(Red + "[!] GitLab rejected the variable (action=" + f[1] + ", http=" + f[2] + ")." + Reset)
		}
		if strings.HasPrefix(l, "ERR|") {
			fmt.Println(Yellow + "   " + strings.TrimPrefix(l, "ERR|") + Reset)
		}
	}
	return false
}
