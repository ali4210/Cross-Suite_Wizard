package security

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type PreFlightReport struct {
	ResolvedPort   int
	PortShifted    bool
	OriginalPort   int
	SysctlPatched  bool
	DinDConfigured bool
}

// ResolvePort checks if a target port is occupied on the remote host and shifts it if necessary
func ResolvePort(client *ssh.Client, targetPort int) (int, bool, error) {
	currentPort := targetPort
	maxAttempts := 20

	for i := 0; i < maxAttempts; i++ {
		cmd := fmt.Sprintf("ss -tulpn | grep ':%d ' || true", currentPort)
		out, err := executeRemoteCommand(client, cmd)
		if err != nil {
			return targetPort, false, err
		}

		if strings.TrimSpace(out) == "" {
			return currentPort, currentPort != targetPort, nil
		}

		currentPort++
	}

	return targetPort, false, fmt.Errorf("could not find an open port starting from %d", targetPort)
}

// TuneKernelSettings verifies and auto-patches Linux kernel parameters for heavy stacks (ELK/SonarQube)
func TuneKernelSettings(client *ssh.Client) (bool, error) {
	patched := false

	// 1. vm.max_map_count (Elasticsearch)
	out, err := executeRemoteCommand(client, "sysctl -n vm.max_map_count || echo 0")
	if err != nil {
		return false, err
	}
	val, _ := strconv.Atoi(strings.TrimSpace(out))
	if val < 262144 {
		fmt.Println("  [!] Low vm.max_map_count detected. Auto-patching kernel parameter...")
		_, err := executeRemoteCommand(client, "sudo sysctl -w vm.max_map_count=262144")
		if err == nil {
			executeRemoteCommand(client, "echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf")
			patched = true
		}
	}

	// 2. net.core.somaxconn
	out, _ = executeRemoteCommand(client, "sysctl -n net.core.somaxconn || echo 128")
	val, _ = strconv.Atoi(strings.TrimSpace(out))
	if val < 1024 {
		fmt.Println("  [!] Low net.core.somaxconn (<1024). Increasing to 4096...")
		executeRemoteCommand(client, "sudo sysctl -w net.core.somaxconn=4096")
		executeRemoteCommand(client, "echo 'net.core.somaxconn=4096' | sudo tee -a /etc/sysctl.conf")
		patched = true
	}

	// 3. fs.file-max
	out, _ = executeRemoteCommand(client, "sysctl -n fs.file-max || echo 65535")
	val, _ = strconv.Atoi(strings.TrimSpace(out))
	if val < 100000 {
		fmt.Println("  [!] fs.file-max is low. Setting to 2097152...")
		executeRemoteCommand(client, "sudo sysctl -w fs.file-max=2097152")
		executeRemoteCommand(client, "echo 'fs.file-max=2097152' | sudo tee -a /etc/sysctl.conf")
		patched = true
	}

	// 4. Swap (if RAM < 4GB)
	ramOut, _ := executeRemoteCommand(client, "free -m | awk '/^Mem:/{print $2}'")
	if ramOut != "" {
		totalRAM, _ := strconv.Atoi(strings.TrimSpace(ramOut))
		if totalRAM < 3900 {
			fmt.Println("  [!] Host RAM under 4GB. Ensuring 4GB swapfile...")
			swapCmd := `if [ $(free -m | awk '/^Swap:/{print $2}') -eq 0 ]; then
				sudo fallocate -l 4G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=4096
				sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
				echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
			fi`
			executeRemoteCommand(client, swapCmd)
			patched = true
		}
	}

	return patched, nil
}

// FixDockerSocket sets up Docker-in-Docker socket permissions and ensures proper group membership
func FixDockerSocket(client *ssh.Client) (bool, error) {
	cmd := `if [ -S /var/run/docker.sock ]; then
		sudo chmod 660 /var/run/docker.sock 2>/dev/null
		sudo chown root:docker /var/run/docker.sock 2>/dev/null
		# Add current user to docker group
		USER=$(whoami)
		sudo usermod -aG docker $USER 2>/dev/null
		echo "OK"
	else
		echo "NOK"
	fi`
	out, err := executeRemoteCommand(client, cmd)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "OK"), nil
}