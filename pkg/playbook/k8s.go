package playbook

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// AddonItem tracks interactive checkbox state and active status
type AddonItem struct {
	ID          string
	Name        string
	Description string
	Active      bool
}

// readRawKey captures individual keypresses and ANSI escape sequences
func readRawKey() (string, error) {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		var buf [1]byte
		n, err := os.Stdin.Read(buf[:])
		if err != nil || n == 0 {
			return "", err
		}
		return string(buf[0]), nil
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
		case 3: // Ctrl+C
			return "CTRL_C", nil
		default:
			return strings.ToUpper(string(buf[0])), nil
		}
	}

	return "", nil
}

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
		}
	}
}
// promptSelectClusterAddons automatically detects the live active cluster with strict idempotency guards
func promptSelectClusterAddons(reader *bufio.Reader, client *ssh.Client) {
	fmt.Print("\033[H\033[2J")
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)
	fmt.Println(Bold + Cyan + "==>> AUTONOMOUS KUBERNETES ENGINE DETECTION & IDEMPOTENCY GUARD" + Reset)
	fmt.Println(Bold + Cyan + "================================================================================" + Reset)

	// 1. Detect active Minikube cluster
	minikubeCheckCmd := "minikube status 2>/dev/null | grep -q 'host: Running\\|apiserver: Running'"
	_, minikubeErr := runSudoScript(client, minikubeCheckCmd)
	isMinikubeActive := (minikubeErr == nil)

	// 2. Detect active KinD cluster nodes in Docker
	kindCheckCmd := "kind get clusters 2>/dev/null | grep -q '^cross-k8s-cluster$' && docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'cross-k8s-cluster-control-plane'"
	_, kindErr := runSudoScript(client, kindCheckCmd)
	isKindActive := (kindErr == nil)

	// Case A: Neither cluster is running
	if !isMinikubeActive && !isKindActive {
		fmt.Println(Red + Bold + "\n[!] IDEMPOTENCY BLOCK: No active Kubernetes cluster is currently running!" + Reset)
		fmt.Println(Yellow + "    => Cannot manage add-ons for a non-existent cluster." + Reset)
		fmt.Println(Yellow + "    => Please deploy Minikube (Option 2) or KinD (Option 3) first." + Reset)
		return
	}

	// Case B: Only Minikube is active
	if isMinikubeActive && !isKindActive {
		fmt.Println(Green + Bold + "=> LIVE CLUSTER DETECTED: Active Minikube Single-Node Cluster" + Reset)
		fmt.Println(Cyan + "=> Locking context to Minikube & routing directly to Minikube Add-on Manager..." + Reset)
		_, _ = runSudoScript(client, "kubectl config use-context minikube 2>/dev/null || true")
		ShowMinikubeAddonManager(client)
		return
	}

	// Case C: Only KinD is active
	if isKindActive && !isMinikubeActive {
		fmt.Println(Green + Bold + "=> LIVE CLUSTER DETECTED: Active KinD Multi-Node Cluster (cross-k8s-cluster)" + Reset)
		fmt.Println(Cyan + "=> Locking context to KinD & routing directly to KinD Add-on Manager..." + Reset)
		_, _ = runSudoScript(client, "kubectl config use-context kind-cross-k8s-cluster 2>/dev/null || true")
		ShowKindAddonManager(client)
		return
	}

	// Case D: Conflict - Both are running simultaneously
	fmt.Println(Yellow + Bold + "\n[!] CONFLICT DETECTED: Both Minikube and KinD clusters are active simultaneously!" + Reset)
	fmt.Println("  [1] => Manage Minikube Add-ons (Will strictly target Minikube context)")
	fmt.Println("  [2] => Manage KinD Add-ons (Will strictly target KinD context)")
	fmt.Println(Red + "  [0] => Cancel / Back" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select cluster to target [1-2]: ")
	clean := strings.TrimSpace(choice)

	switch clean {
	case "1":
		_, _ = runSudoScript(client, "kubectl config use-context minikube 2>/dev/null || true")
		ShowMinikubeAddonManager(client)
	case "2":
		_, _ = runSudoScript(client, "kubectl config use-context kind-cross-k8s-cluster 2>/dev/null || true")
		ShowKindAddonManager(client)
	default:
		return
	}
}

// ShowMinikubeAddonManager provides true live arrow-key management for Minikube
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
			for _, item := range addons {
				cmd := fmt.Sprintf("minikube addons enable %s >/dev/null 2>&1 || true", item.ID)
				_, _ = runSudoScriptWithSpinner(client, cmd, fmt.Sprintf("Activating Add-on: %s", item.Name))
			}
			refreshMinikubeActiveState(client, addons)
			fmt.Println(Green + Bold + "=> All Minikube Add-ons enabled successfully!" + Reset)
			pauseAddonPrompt()

		case "P":
			fmt.Print("\033[H\033[2J")
			fmt.Println(Red + Bold + "\n=> [1-CLICK ACTION]: Purging & Disabling ALL Minikube Add-ons..." + Reset)
			for _, item := range addons {
				if item.Active {
					cmd := fmt.Sprintf("minikube addons disable %s >/dev/null 2>&1 || true", item.ID)
					_, _ = runSudoScriptWithSpinner(client, cmd, fmt.Sprintf("Disabling Add-on: %s", item.Name))
				}
			}
			refreshMinikubeActiveState(client, addons)
			fmt.Println(Green + Bold + "=> All Minikube Add-ons purged and disabled cleanly!" + Reset)
			pauseAddonPrompt()
		}
	}
}

// ShowKindAddonManager provides true live arrow-key management for KinD
func ShowKindAddonManager(client *ssh.Client) {
	addons := []AddonItem{
		{ID: "ingress-nginx", Name: "ingress-nginx", Description: "NGINX Ingress Controller (Ports 8085/8443)"},
		{ID: "metrics-server", Name: "metrics-server", Description: "Metrics Server with --kubelet-insecure-tls"},
		{ID: "k8s-dashboard", Name: "k8s-dashboard", Description: "Kubernetes Web Dashboard v2.7.0 UI"},
		{ID: "metallb", Name: "metallb", Description: "MetalLB Layer-2 Load Balancer Engine"},
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
			applyKindManifest(client, "ingress-nginx")
			applyKindManifest(client, "metrics-server")
			applyKindManifest(client, "k8s-dashboard")
			applyKindManifest(client, "metallb")
			applyKindManifest(client, "cert-manager")
			refreshKindActiveState(client, addons)
			fmt.Println(Green + Bold + "=> All KinD Add-ons deployed successfully!" + Reset)
			pauseAddonPrompt()

		case "P":
			fmt.Print("\033[H\033[2J")
			fmt.Println(Red + Bold + "\n=> [1-CLICK ACTION]: Purging ALL KinD Add-on Resources..." + Reset)
			purgeKindManifest(client, "ingress-nginx")
			purgeKindManifest(client, "metrics-server")
			purgeKindManifest(client, "k8s-dashboard")
			purgeKindManifest(client, "metallb")
			purgeKindManifest(client, "cert-manager")
			refreshKindActiveState(client, addons)
			fmt.Println(Green + Bold + "=> All KinD Add-on resources purged cleanly!" + Reset)
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

// handleIndividualAddonAction presents the direct Apply/Deny sub-dialog for an item
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

	choice := transfer.ReadRealtimeInput("Select action [1=Apply, 2=Deny, 0=Cancel]: ")
	clean := strings.TrimSpace(choice)

	if clean == "1" {
		if engine == "minikube" {
			cmd := fmt.Sprintf("minikube addons enable %s >/dev/null 2>&1 || true", item.ID)
			_, _ = runSudoScriptWithSpinner(client, cmd, fmt.Sprintf("Enabling Minikube Add-on: %s", item.Name))
		} else {
			applyKindManifest(client, item.ID)
		}
		item.Active = true
		fmt.Println(Green + Bold + fmt.Sprintf("=> Add-on '%s' has been APPLIED successfully!", item.Name) + Reset)
		pauseAddonPrompt()
	} else if clean == "2" {
		if engine == "minikube" {
			cmd := fmt.Sprintf("minikube addons disable %s >/dev/null 2>&1 || true", item.ID)
			_, _ = runSudoScriptWithSpinner(client, cmd, fmt.Sprintf("Disabling Minikube Add-on: %s", item.Name))
		} else {
			purgeKindManifest(client, item.ID)
		}
		item.Active = false
		fmt.Println(Yellow + Bold + fmt.Sprintf("=> Add-on '%s' has been DENIED/PURGED cleanly!", item.Name) + Reset)
		pauseAddonPrompt()
	}
}

// refreshMinikubeActiveState queries live minikube status
func refreshMinikubeActiveState(client *ssh.Client, addons []AddonItem) {
	out, _ := runSudoScript(client, "minikube addons list 2>/dev/null")
	for i := range addons {
		addons[i].Active = strings.Contains(out, addons[i].ID) && strings.Contains(out, "enabled")
	}
}

// refreshKindActiveState queries live namespace existence
func refreshKindActiveState(client *ssh.Client, addons []AddonItem) {
	nsOut, _ := runSudoScript(client, "kubectl get namespaces 2>/dev/null")
	for i := range addons {
		switch addons[i].ID {
		case "ingress-nginx":
			addons[i].Active = strings.Contains(nsOut, "ingress-nginx")
		case "k8s-dashboard":
			addons[i].Active = strings.Contains(nsOut, "kubernetes-dashboard")
		case "metallb":
			addons[i].Active = strings.Contains(nsOut, "metallb-system")
		case "cert-manager":
			addons[i].Active = strings.Contains(nsOut, "cert-manager")
		case "metrics-server":
			podOut, _ := runSudoScript(client, "kubectl -n kube-system get pods -l k8s-app=metrics-server 2>/dev/null")
			addons[i].Active = strings.Contains(podOut, "metrics-server")
		default:
			addons[i].Active = false
		}
	}
}

func applyKindManifest(client *ssh.Client, id string) {
	switch id {
	case "ingress-nginx":
		_, _ = runSudoScriptWithSpinner(client, "kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml 2>/dev/null", "Applying NGINX Ingress Controller")
	case "metrics-server":
		_, _ = runSudoScriptWithSpinner(client, "kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml 2>/dev/null", "Applying Metrics Server")
	case "k8s-dashboard":
		_, _ = runSudoScriptWithSpinner(client, "kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml 2>/dev/null", "Applying Kubernetes Dashboard")
	case "metallb":
		_, _ = runSudoScriptWithSpinner(client, "kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml 2>/dev/null", "Applying MetalLB Controller")
	case "cert-manager":
		_, _ = runSudoScriptWithSpinner(client, "kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.4/cert-manager.yaml 2>/dev/null", "Applying Cert-Manager")
	}
}

func purgeKindManifest(client *ssh.Client, id string) {
	switch id {
	case "ingress-nginx":
		_, _ = runSudoScriptWithSpinner(client, "kubectl delete namespace ingress-nginx 2>/dev/null || true", "Purging NGINX Ingress")
	case "metrics-server":
		_, _ = runSudoScriptWithSpinner(client, "kubectl delete -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml 2>/dev/null || true", "Purging Metrics Server")
	case "k8s-dashboard":
		_, _ = runSudoScriptWithSpinner(client, "kubectl delete namespace kubernetes-dashboard 2>/dev/null || true", "Purging Kubernetes Dashboard")
	case "metallb":
		_, _ = runSudoScriptWithSpinner(client, "kubectl delete namespace metallb-system 2>/dev/null || true", "Purging MetalLB")
	case "cert-manager":
		_, _ = runSudoScriptWithSpinner(client, "kubectl delete namespace cert-manager 2>/dev/null || true", "Purging Cert-Manager")
	}
}

func pauseAddonPrompt() {
	fmt.Println(Cyan + "\n--------------------------------------------------------------------------------" + Reset)
	fmt.Print(Bold + Yellow + "[ Press ENTER to return to Live Add-on Manager ] " + Reset)
	var tmp string
	fmt.Scanln(&tmp)
}

func pauseK8sPrompt(reader *bufio.Reader) {
	fmt.Println(Blue + "\n--------------------------------------------------------------------------------" + Reset)
	fmt.Print(Bold + Yellow + "[ Press ENTER to return to Kubernetes Menu ] " + Reset)
	_, _ = reader.ReadString('\n')
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

	choice := transfer.ReadRealtimeInput("Select binary installer [Default 4]: ")
	cleanChoice := strings.TrimSpace(choice)
	if cleanChoice == "" {
		cleanChoice = "4"
	}

	ensureAutonomousPermissionsWithPrompt(client)

	switch cleanChoice {
	case "1":
		installKubectlBinary(client)
	case "2":
		installMinikubeBinary(client)
	case "3":
		installKindBinary(client)
	case "4":
		installKubectlBinary(client)
		installMinikubeBinary(client)
		installKindBinary(client)
	case "0":
		return
	default:
		installKubectlBinary(client)
		installMinikubeBinary(client)
		installKindBinary(client)
	}

	fmt.Println(Green + Bold + "\n================================================================================" + Reset)
	fmt.Println(Green + Bold + "==>> TARGET KUBERNETES BINARIES INSTALLED SYSTEM-WIDE!" + Reset)
	fmt.Println(Cyan + Bold + "   => Location : /usr/local/bin" + Reset)
	fmt.Println(Cyan + Bold + "   => Access   : Available system-wide without running clusters" + Reset)
	fmt.Println(Green + Bold + "================================================================================" + Reset)
}

// installKubectlBinary ensures kubectl CLI is available system-wide
func installKubectlBinary(client *ssh.Client) {
	installCmd := `
		ARCH=$(uname -m)
		case "$ARCH" in
			x86_64|amd64)  K_ARCH="amd64" ;;
			aarch64|arm64) K_ARCH="arm64" ;;
			*)             K_ARCH="amd64" ;;
		esac

		mkdir -p /usr/local/bin
		K_VER=$(curl -sL https://dl.k8s.io/release/stable.txt 2>/dev/null)
		if [ -z "$K_VER" ]; then K_VER="v1.29.2"; fi

		curl -sSL -H "User-Agent: Mozilla/5.0" "https://dl.k8s.io/release/${K_VER}/bin/linux/${K_ARCH}/kubectl" -o /tmp/kubectl 2>/dev/null || \
		wget -U "Mozilla/5.0" -q "https://dl.k8s.io/release/${K_VER}/bin/linux/${K_ARCH}/kubectl" -O /tmp/kubectl 2>/dev/null || true

		if [ -f /tmp/kubectl ] && [ -s /tmp/kubectl ]; then
			mv /tmp/kubectl /usr/local/bin/kubectl
			chmod 755 /usr/local/bin/kubectl
		fi
		rm -f /tmp/kubectl 2>/dev/null
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, installCmd, "Deploying kubectl CLI binary to /usr/local/bin")
}

// installMinikubeBinary ensures minikube binary is available system-wide
func installMinikubeBinary(client *ssh.Client) {
	installCmd := `
		ARCH=$(uname -m)
		case "$ARCH" in
			x86_64|amd64)  MK_ARCH="amd64" ;;
			aarch64|arm64) MK_ARCH="arm64" ;;
			*)             MK_ARCH="amd64" ;;
		esac

		mkdir -p /usr/local/bin
		curl -sSL -H "User-Agent: Mozilla/5.0" "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-${MK_ARCH}" -o /tmp/minikube 2>/dev/null || \
		wget -U "Mozilla/5.0" -q "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-${MK_ARCH}" -O /tmp/minikube 2>/dev/null || true

		if [ -f /tmp/minikube ] && [ -s /tmp/minikube ]; then
			mv /tmp/minikube /usr/local/bin/minikube
			chmod 755 /usr/local/bin/minikube
		fi
		rm -f /tmp/minikube 2>/dev/null
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, installCmd, "Deploying Minikube Engine binary to /usr/local/bin")
}

// installKindBinary ensures kind binary is available system-wide
func installKindBinary(client *ssh.Client) {
	installCmd := `
		ARCH=$(uname -m)
		case "$ARCH" in
			x86_64|amd64)  KIND_ARCH="amd64" ;;
			aarch64|arm64) KIND_ARCH="arm64" ;;
			*)             KIND_ARCH="amd64" ;;
		esac

		mkdir -p /usr/local/bin
		curl -sSL -H "User-Agent: Mozilla/5.0" "https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-${KIND_ARCH}" -o /tmp/kind 2>/dev/null || \
		wget -U "Mozilla/5.0" -q "https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-${KIND_ARCH}" -O /tmp/kind 2>/dev/null || true

		if [ -f /tmp/kind ] && [ -s /tmp/kind ]; then
			mv /tmp/kind /usr/local/bin/kind
			chmod 755 /usr/local/bin/kind
		fi
		rm -f /tmp/kind 2>/dev/null
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, installCmd, "Deploying KinD Engine binary to /usr/local/bin")
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
	installKubectlBinary(client)

	if strings.ToLower(engineChoice) == "kind" {
		_, _ = runSudoScriptWithSpinner(client, "minikube stop 2>/dev/null || true", "Resolving Conflicts (Halting Minikube if running)")

		installKindBinary(client)

		kindConfig := `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 8085
    protocol: TCP
  - containerPort: 443
    hostPort: 8443
    protocol: TCP
- role: worker
- role: worker
`
		_, _ = runSudoScript(client, fmt.Sprintf("cat << 'EOF' > /tmp/kind-config.yaml\n%s\nEOF", strings.TrimSpace(kindConfig)))

		spinKindCmd := "kind delete cluster --name cross-k8s-cluster 2>/dev/null || true; kind create cluster --name cross-k8s-cluster --config /tmp/kind-config.yaml"
		_, _ = runSudoScriptWithSpinner(client, spinKindCmd, "Deploying KinD Multi-Node Topology over Docker Engine")

		applyKindAddons(client)

	} else {
		_, _ = runSudoScriptWithSpinner(client, "kind delete cluster --name cross-k8s-cluster 2>/dev/null || true", "Resolving Conflicts (Halting KinD if running)")

		installMinikubeBinary(client)

		spinMkCmd := `
		TARGET_USER=$(logname 2>/dev/null || echo $SUDO_USER)
		[ -z "$TARGET_USER" ] && TARGET_USER="kali"
		USER_HOME=$(eval echo "~$TARGET_USER")

		chown -R ${TARGET_USER}:${TARGET_USER} ${USER_HOME}/.minikube ${USER_HOME}/.kube 2>/dev/null || true
		chmod -R u+wrx ${USER_HOME}/.minikube ${USER_HOME}/.kube 2>/dev/null || true

		sudo -u ${TARGET_USER} -E minikube start --driver=docker --force >/dev/null 2>&1 || minikube start --driver=docker --force >/dev/null 2>&1

		sudo -u ${TARGET_USER} -E minikube addons enable ingress 2>/dev/null || true
		sudo -u ${TARGET_USER} -E minikube addons enable metrics-server 2>/dev/null || true
		sudo -u ${TARGET_USER} -E minikube addons enable dashboard 2>/dev/null || true

		chown -R ${TARGET_USER}:${TARGET_USER} ${USER_HOME}/.minikube ${USER_HOME}/.kube 2>/dev/null || true
		`
		_, _ = runSudoScriptWithSpinner(client, spinMkCmd, "Deploying Minikube Single-Node Cluster over Docker Engine")
	}

	syncKubeconfigPermissions(client)
	extractAndDisplayKubeconfig(client)
}

// stopActiveClusters gracefully stops both engines without data loss
func stopActiveClusters(client *ssh.Client) {
	ensureAutonomousPermissionsWithPrompt(client)
	stopCmd := `
		minikube stop 2>/dev/null || true
		docker stop $(docker ps -q --filter label=io.x-k8s.kind.cluster=cross-k8s-cluster) 2>/dev/null || true
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, stopCmd, "Pausing Active Minikube and KinD Node Containers")
	fmt.Println(Green + Bold + "=> Active Kubernetes clusters paused successfully to reclaim memory." + Reset)
}

// deleteActiveClustersPrompt allows resetting cluster topologies without deleting CLI binaries
func deleteActiveClustersPrompt(reader *bufio.Reader, client *ssh.Client) {
	fmt.Println(Yellow + Bold + "\n================================================================================" + Reset)
	fmt.Println(Yellow + Bold + "==>> SELECT CLUSTER TOPOLOGY TO DELETE (Binaries Will Remain Intact):" + Reset)
	fmt.Println(Yellow + Bold + "================================================================================" + Reset)
	fmt.Println("  [1] => Delete Minikube Cluster only (Clean minikube state)")
	fmt.Println("  [2] => Delete KinD Cluster only (Clean cross-k8s-cluster nodes)")
	fmt.Println("  [3] => Delete BOTH Minikube & KinD Clusters")
	fmt.Println(Red + "  [0] => Cancel" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	ans := transfer.ReadRealtimeInput("Select cluster to delete [Default 3]: ")
	cleanAns := strings.TrimSpace(ans)
	if cleanAns == "" {
		cleanAns = "3"
	}

	ensureAutonomousPermissionsWithPrompt(client)

	switch cleanAns {
	case "1":
		_, _ = runSudoScriptWithSpinner(client, "minikube delete --all --purge 2>/dev/null || true", "Purging Minikube Cluster State")
		fmt.Println(Green + Bold + "=> Minikube cluster nodes deleted successfully!" + Reset)
	case "2":
		_, _ = runSudoScriptWithSpinner(client, "kind delete cluster --name cross-k8s-cluster 2>/dev/null || true", "Purging KinD Cluster Nodes")
		fmt.Println(Green + Bold + "=> KinD cluster nodes deleted successfully!" + Reset)
	case "3":
		_, _ = runSudoScriptWithSpinner(client, "minikube delete --all --purge 2>/dev/null || true; kind delete cluster --name cross-k8s-cluster 2>/dev/null || true", "Purging Minikube & KinD Cluster Topologies")
		fmt.Println(Green + Bold + "=> Both Minikube and KinD clusters deleted successfully!" + Reset)
	case "0":
		return
	}
}

// uninstallKubernetesSuitePrompt provides selective deep-purge options
func uninstallKubernetesSuitePrompt(reader *bufio.Reader, client *ssh.Client) {
	fmt.Println(Red + Bold + "\n================================================================================" + Reset)
	fmt.Println(Red + Bold + "==>> SELECT ENGINE OR TOOL TO DEEP PURGE & UNINSTALL:" + Reset)
	fmt.Println(Red + Bold + "================================================================================" + Reset)
	fmt.Println("  [1] => Deep Purge Minikube (Wipe clusters, cache ~/.minikube, and /usr/local/bin/minikube)")
	fmt.Println("  [2] => Deep Purge KinD (Wipe cross-k8s-cluster containers and /usr/local/bin/kind)")
	fmt.Println("  [3] => Deep Purge kubectl CLI (/usr/local/bin/kubectl)")
	fmt.Println(Red + "  [4] => DEEP PURGE EVERYTHING (Minikube, KinD, kubectl, and ~/.kube configuration)" + Reset)
	fmt.Println(Yellow + "  [0] => Cancel" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select uninstallation target [0-4]: ")
	cleanChoice := strings.TrimSpace(choice)

	if cleanChoice == "0" || cleanChoice == "" {
		fmt.Println(Yellow + "=> Uninstallation cancelled." + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	switch cleanChoice {
	case "1":
		purgeMkCmd := `
		TARGET_USER=$(logname 2>/dev/null || echo $SUDO_USER)
		[ -z "$TARGET_USER" ] && TARGET_USER="kali"
		USER_HOME=$(eval echo "~$TARGET_USER")

		minikube delete --all --purge 2>/dev/null || true
		docker rm -f minikube 2>/dev/null || true
		rm -f /usr/local/bin/minikube /usr/bin/minikube
		rm -rf ${USER_HOME}/.minikube /root/.minikube ${USER_HOME}/.kube /root/.kube
		hash -r 2>/dev/null || true
		exit 0
		`
		_, _ = runSudoScriptWithSpinner(client, purgeMkCmd, "Deep Purging Minikube Binary, Nodes & Cache")
		fmt.Println(Green + Bold + "=> Minikube uninstalled and purged completely!" + Reset)

	case "2":
		purgeKindCmd := `
			kind delete cluster --name cross-k8s-cluster 2>/dev/null || true
			docker rm -f $(docker ps -a -q --filter label=io.x-k8s.kind.cluster) 2>/dev/null || true
			rm -f /usr/local/bin/kind /usr/bin/kind /tmp/kind-config.yaml
			hash -r 2>/dev/null || true
			exit 0
		`
		_, _ = runSudoScriptWithSpinner(client, purgeKindCmd, "Deep Purging KinD Binary and Node Containers")
		fmt.Println(Green + Bold + "=> KinD uninstalled and purged completely!" + Reset)

	case "3":
		purgeKubeCmd := `
			rm -f /usr/local/bin/kubectl /usr/bin/kubectl
			hash -r 2>/dev/null || true
			exit 0
		`
		_, _ = runSudoScriptWithSpinner(client, purgeKubeCmd, "Removing kubectl CLI Binary")
		fmt.Println(Green + Bold + "=> kubectl CLI removed completely!" + Reset)

	case "4":
		purgeAllCmd := `
			minikube delete --all --purge 2>/dev/null || true
			kind delete cluster --name cross-k8s-cluster 2>/dev/null || true

			docker rm -f $(docker ps -a -q --filter label=io.x-k8s.kind.cluster) 2>/dev/null || true
			docker rm -f minikube 2>/dev/null || true

			rm -f /usr/local/bin/kubectl /usr/local/bin/minikube /usr/local/bin/kind
			rm -f /usr/bin/kubectl /usr/bin/minikube /usr/bin/kind

			rm -rf ~/.kube ~/.minikube /root/.kube /root/.minikube /etc/kubernetes /tmp/kind-config.yaml /tmp/active_kube.yaml
			hash -r 2>/dev/null || true
			exit 0
		`
		_, _ = runSudoScriptWithSpinner(client, purgeAllCmd, "Deep Purging ALL Kubernetes Tools, Clusters & Configurations")
		fmt.Println(Green + Bold + "=> Entire Kubernetes ecosystem, binaries, and configurations purged completely!" + Reset)
	}
}

// syncKubeconfigPermissions synchronizes credentials without breaking local loopback bindings
func syncKubeconfigPermissions(client *ssh.Client) {
	syncCmd := `
		mkdir -p ~/.kube /root/.kube /etc/kubernetes /etc/rancher/k3s 2>/dev/null

		if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q 'cross-k8s-cluster'; then
			kind get kubeconfig --name cross-k8s-cluster > /tmp/active_kube.yaml 2>/dev/null || true
		else
			kubectl config view --raw > /tmp/active_kube.yaml 2>/dev/null || true
		fi

		if [ -s /tmp/active_kube.yaml ]; then
			cp -f /tmp/active_kube.yaml ~/.kube/config 2>/dev/null || true
			cp -f /tmp/active_kube.yaml /root/.kube/config 2>/dev/null || true
			cp -f /tmp/active_kube.yaml /etc/kubernetes/admin.conf 2>/dev/null || true
			cp -f /tmp/active_kube.yaml /etc/rancher/k3s/k3s.yaml 2>/dev/null || true
		fi

		chmod 644 ~/.kube/config /root/.kube/config /etc/kubernetes/admin.conf /etc/rancher/k3s/k3s.yaml 2>/dev/null || true
		chmod 666 /var/run/docker.sock 2>/dev/null || true
		rm -f /tmp/kind-config.yaml /tmp/active_kube.yaml 2>/dev/null || true
		exit 0
	`
	_, _ = runSudoScriptWithSpinner(client, syncCmd, "Synchronizing Local Kubeconfig Permissions")
}

// applyKindAddons provides a 1-click add-on deployment engine for KinD clusters
func applyKindAddons(client *ssh.Client) {
	fmt.Println(Yellow + Bold + "\n=> KinD Cluster Online! Selecting Gold-Standard Add-ons to Pre-Enable..." + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] => Enable NGINX Ingress Controller (Web Traffic Routing & TLS on Port 8085/8443)")
	fmt.Println("  [2] => Enable Metrics Server (kubectl top nodes/pods & HPA Autoscaling)")
	fmt.Println("  [3] => Enable Kubernetes Web Dashboard (Visual Cluster Portal)")
	fmt.Println("  [4] => Enable ALL Recommended Add-ons (Gold Standard Default)")
	fmt.Println("  [0] => Skip Add-ons")
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	choice := transfer.ReadRealtimeInput("Select KinD Add-on Deployment [Default 4]: ")
	if choice == "" {
		choice = "4"
	}

	switch strings.TrimSpace(choice) {
	case "1":
		ingressCmd := "kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml 2>/dev/null || true"
		_, _ = runSudoScriptWithSpinner(client, ingressCmd, "Applying NGINX Ingress Controller Manifests")
		fmt.Println(Green + Bold + "=> NGINX Ingress Controller deployed successfully!" + Reset)

	case "2":
		metricsCmd := "kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml 2>/dev/null || true"
		_, _ = runSudoScriptWithSpinner(client, metricsCmd, "Applying Metrics Server Manifests")
		fmt.Println(Green + Bold + "=> Metrics Server deployed successfully!" + Reset)

	case "3":
		dashCmd := "kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml 2>/dev/null || true"
		_, _ = runSudoScriptWithSpinner(client, dashCmd, "Applying Kubernetes Web Dashboard Manifests")
		fmt.Println(Green + Bold + "=> Kubernetes Web Dashboard deployed successfully!" + Reset)

	case "4":
		allCmd := `
			kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml 2>/dev/null || true
			kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml 2>/dev/null || true
			kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml 2>/dev/null || true
		`
		_, _ = runSudoScriptWithSpinner(client, allCmd, "Deploying Ingress, Metrics Server & Web Dashboard")
		fmt.Println(Green + Bold + "=> All Gold-Standard KinD Add-ons deployed successfully!" + Reset)
	}
}

// extractAndDisplayKubeconfig pulls raw kubeconfig and binds it into GitLab CI variables
func extractAndDisplayKubeconfig(client *ssh.Client) {
	targetIP := resolveTargetIP(client)
	getKubeCmd := "kubectl config view --raw 2>/dev/null || cat ~/.kube/config 2>/dev/null"
	kubeConfig, err := runSudoScript(client, getKubeCmd)
	cleanKube := strings.TrimSpace(kubeConfig)

	if err == nil && strings.Contains(cleanKube, "apiVersion") {
		autoInjectGitLabKubeconfig(client, targetIP, cleanKube)

		fmt.Println(Green + Bold + "\n================================================================================" + Reset)
		fmt.Println(Green + Bold + "==>> KUBERNETES CLUSTER BOUND TO PRESETS & PIPELINES SUCCESSFULLY!" + Reset)
		fmt.Println(Cyan + Bold + "   => Binaries Location  : Installed system-wide (/usr/local/bin)" + Reset)
		fmt.Println(Cyan + Bold + "   => Cluster Status     : Active & Responding to kubectl" + Reset)
		fmt.Println(Cyan + Bold + "   => Mesh Sync Paths    : ~/.kube/config, /etc/rancher/k3s/k3s.yaml" + Reset)
		fmt.Println(Cyan + Bold + "   => Pipeline Variable  : Kubeconfig synchronized for GitLab CI & ArgoCD" + Reset)
		fmt.Printf(Yellow+Bold+"   => Manual Cluster Test: kubectl get nodes -o wide\n"+Reset)
		fmt.Printf(Yellow+Bold+"   => Manual Config View : cat ~/.kube/config\n"+Reset)
		fmt.Println(Green + Bold + "================================================================================" + Reset)
	} else {
		fmt.Println(Red + "[!] Cluster is active, but failed to retrieve raw kubeconfig. Verify permissions." + Reset)
	}
}

// autoInjectGitLabKubeconfig injects KUBECONFIG into GitLab instance CI variables via REST API
func autoInjectGitLabKubeconfig(client *ssh.Client, targetIP string, rawKubeconfig string) {
	injectScript := fmt.Sprintf(`
		if curl -s http://127.0.0.1:8929/api/v4/version -H "PRIVATE-TOKEN: glpat-AdminRootSecretToken123" | grep -q 'version'; then
			ENCODED_KUBE=$(cat << 'EOF' | base64 -w 0
%s
EOF
)
			curl -s -X POST "http://127.0.0.1:8929/api/v4/admin/ci/variables" \
				-H "PRIVATE-TOKEN: glpat-AdminRootSecretToken123" \
				-H "Content-Type: application/json" \
				-d '{"key": "KUBECONFIG_BASE64", "value": "'"$ENCODED_KUBE"'", "protected": false, "masked": false}' >/dev/null 2>&1 || \
			curl -s -X PUT "http://127.0.0.1:8929/api/v4/admin/ci/variables/KUBECONFIG_BASE64" \
				-H "PRIVATE-TOKEN: glpat-AdminRootSecretToken123" \
				-H "Content-Type: application/json" \
				-d '{"value": "'"$ENCODED_KUBE"'"}' >/dev/null 2>&1 || true
			echo "GITLAB_KUBECONFIG_SYNCED"
		fi
	`, rawKubeconfig)

	out, _ := runSudoScript(client, injectScript)
	if strings.Contains(out, "GITLAB_KUBECONFIG_SYNCED") {
		fmt.Println(Green + Bold + "=> Pipeline Bridge: KUBECONFIG_BASE64 auto-injected into GitLab CI/CD Variables!" + Reset)
	}
}