package shell

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"cross-ssh/pkg/osdetect"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	Reset  = "\033[0m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Red    = "\033[31m"
	Cyan   = "\033[36m"
	Blue   = "\033[34m"
	Bold   = "\033[1m"
)

func StartInteractiveTTY(client *ssh.Client, targetOS osdetect.TargetOS) error {
	reader := bufio.NewReader(os.Stdin)

	// Determine shell command to launch
	shellCmd := ""
	if targetOS == osdetect.OSWindows {
		shellCmd = resolveWindowsShell(reader, client)
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Capture terminal state for raw mode TTY
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw terminal mode: %w", err)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
	}()

	width, height, err := term.GetSize(fd)
	if err != nil {
		width, height = 80, 24
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	termType := "xterm-256color"
	if targetOS == osdetect.OSWindows {
		termType = "vt100"
	}

	if err := session.RequestPty(termType, height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// Launch explicitly selected shell on Windows or standard default shell on Linux
	if targetOS == osdetect.OSWindows && shellCmd != "" {
		if err := session.Start(shellCmd); err != nil {
			_ = session.Start("cmd.exe")
		}
	} else {
		if err := session.Shell(); err != nil {
			return fmt.Errorf("failed to start shell: %w", err)
		}
	}

	_ = session.Wait()
	return nil
}

// resolveWindowsShell handles health checks and shell selection for Windows targets
func resolveWindowsShell(reader *bufio.Reader, client *ssh.Client) string {
	fmt.Println("\n" + Cyan + Bold + "================================================================================" + Reset)
	fmt.Println(Cyan + Bold + "=== WINDOWS TTY SHELL ROUTER & HEALTH CHECK ENGINE ===" + Reset)
	fmt.Println(Cyan + Bold + "================================================================================" + Reset)

	hasPortablePwsh := checkRemoteExecutableWithTimeout(client, `"%USERPROFILE%\.pwsh7\pwsh.exe" -v`, 2*time.Second)
	hasSystemPwsh := checkRemoteExecutableWithTimeout(client, "pwsh -v", 2*time.Second)
	hasPowerShell := checkRemoteExecutableWithTimeout(client, "powershell -Command \"$PSVersionTable.PSVersion\"", 2*time.Second)
	hasSystemGitBash := checkRemoteExecutableWithTimeout(client, `cmd.exe /c if exist "C:\Program Files\Git\bin\bash.exe" (exit 0) else (exit 1)`, 2*time.Second)
	
	// Evaluates if WSL2 is both installed AND has a ready Linux distribution
	hasWSL := checkRemoteExecutableWithTimeout(client, "wsl.exe -e uname", 2*time.Second)

	var defaultShell string
	var pwshCmdPath string

	if hasSystemPwsh {
		fmt.Println(Green + "  [✔] PowerShell Core 7.x (System-Wide pwsh.exe) : INSTALLED & READY" + Reset)
		defaultShell = "pwsh.exe"
		pwshCmdPath = "pwsh.exe"
	} else if hasPortablePwsh {
		fmt.Println(Green + "  [✔] PowerShell Core 7.x (Portable ~/.pwsh7/pwsh.exe) : INSTALLED & READY" + Reset)
		defaultShell = `"%USERPROFILE%\.pwsh7\pwsh.exe"`
		pwshCmdPath = `"%USERPROFILE%\.pwsh7\pwsh.exe"`
	} else {
		fmt.Println(Yellow + "  [!] PowerShell Core 7.x (pwsh.exe) : NOT INSTALLED" + Reset)
	}

	if hasPowerShell {
		fmt.Println(Green + "  [✔] Windows PowerShell (powershell.exe) : INSTALLED & READY" + Reset)
		if defaultShell == "" {
			defaultShell = "powershell.exe"
		}
	} else {
		fmt.Println(Red + "  [!] Windows PowerShell (powershell.exe) : UNHEALTHY OR DISABLED" + Reset)
	}

	fmt.Println(Green + "  [✔] Command Prompt (cmd.exe) : BUILT-IN SYSTEM DEFAULT" + Reset)
	if defaultShell == "" {
		defaultShell = "cmd.exe"
	}

	if hasWSL {
		fmt.Println(Green + "  [✔] Native WSL2 Linux Subsystem : INSTALLED & READY" + Reset)
	}

	fmt.Println(Green + "  [✔] Master POSIX Translation Engine : ALWAYS READY" + Reset)

	if hasSystemGitBash {
		fmt.Println(Green + "  [✔] Native Git Bash (\"C:\\Program Files\\Git\\bin\\bash.exe\") : INSTALLED & READY" + Reset)
	}

	// Manual shell switch prompt
	fmt.Println("\n" + Bold + "Select Interactive TTY Shell to Launch:" + Reset)
	if pwshCmdPath != "" {
		fmt.Printf("  [1] PowerShell Core 7.x (%s) %s\n", pwshCmdPath, isDefaultTag(defaultShell == pwshCmdPath))
	} else {
		fmt.Printf("  [1] PowerShell Core 7.x (pwsh.exe - Unavailable)\n")
	}
	fmt.Printf("  [2] Windows PowerShell (powershell.exe) %s\n", isDefaultTag(defaultShell == "powershell.exe"))
	fmt.Printf("  [3] Classic Command Prompt (cmd.exe) %s\n", isDefaultTag(defaultShell == "cmd.exe"))
	
	if hasWSL {
		fmt.Println(Green + Bold + "  [4] 🚀 Genuine WSL2 Linux Kernel Shell (wsl.exe ~)" + Reset)
	}
	
	fmt.Println(Yellow + Bold + "  [5] ⚡ Master POSIX-to-PowerShell Translation Engine (Windows System Bridge)" + Reset)
	fmt.Println("      (Runs 'rm -rf', 'ls -la', 'cp -r', 'grep', 'top', 'free', 'df', 'systemctl', 'apt')")

	if hasSystemGitBash {
		fmt.Println(Green + "  [6] 💻 Native Git Bash (\"C:\\Program Files\\Git\\bin\\bash.exe\")" + Reset)
	}

	fmt.Println("  [Enter] Launch Auto-Detected Default Shell")
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	fmt.Print(Bold + "Choice [Select Number or Enter]: " + Reset)
	choiceInput, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(choiceInput)

	switch choice {
	case "1":
		if pwshCmdPath != "" {
			return pwshCmdPath
		}
		return defaultShell
	case "2":
		return "powershell.exe"
	case "3":
		return "cmd.exe"
	case "4":
		if hasWSL {
			fmt.Println(Green + Bold + "\n[+] Launching Native WSL2 Linux Kernel Shell..." + Reset)
			return "wsl.exe ~"
		}
		fmt.Println(Yellow + "[!] WSL2 is not installed or configured on target. Launching Default Shell..." + Reset)
		return defaultShell
	case "5":
		fmt.Println(Yellow + Bold + "\n[+] Launching Master POSIX Translation Engine..." + Reset)
		return getUniversalPowerShellTranslatorCommand(client)
	case "6":
		if hasSystemGitBash {
			return `"C:\Program Files\Git\bin\bash.exe" --login -i`
		}
		fmt.Println(Yellow + "[!] Git Bash not found on target host. Launching Default Shell..." + Reset)
		return defaultShell
	default:
		return defaultShell
	}
}

func checkRemoteExecutableWithTimeout(client *ssh.Client, cmd string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan bool, 1)

	go func() {
		sess, err := client.NewSession()
		if err != nil {
			done <- false
			return
		}
		defer sess.Close()

		err = sess.Run(cmd)
		done <- (err == nil)
	}()

	select {
	case res := <-done:
		return res
	case <-ctx.Done():
		return false
	}
}

func getUniversalPowerShellTranslatorCommand(client *ssh.Client) string {
	remoteProfilePath := `C:\Windows\Temp\cross_posix_profile.ps1`

	profileScript := `# Cross-Suite Wizard Universal POSIX Master Translation Engine
Remove-Item Alias:rm -ErrorAction SilentlyContinue
Remove-Item Alias:ls -ErrorAction SilentlyContinue
Remove-Item Alias:cp -ErrorAction SilentlyContinue
Remove-Item Alias:mv -ErrorAction SilentlyContinue
Remove-Item Alias:cat -ErrorAction SilentlyContinue
Remove-Item Alias:clear -ErrorAction SilentlyContinue
Remove-Item Alias:curl -ErrorAction SilentlyContinue
Remove-Item Alias:wget -ErrorAction SilentlyContinue

function global:rm {
    param([Parameter(ValueFromRemainingArguments=$true)]$args)
    $flags = $args | Where-Object { $_ -like '-*' }
    $paths = $args | Where-Object { $_ -notlike '-*' }
    $recurse = $false; $force = $false
    foreach ($f in $flags) {
        if ($f -match 'r') { $recurse = $true }
        if ($f -match 'f') { $force = $true }
    }
    foreach ($p in $paths) {
        if ($recurse -and $force) { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue }
        elseif ($recurse) { Remove-Item -Path $p -Recurse -ErrorAction SilentlyContinue }
        elseif ($force) { Remove-Item -Path $p -Force -ErrorAction SilentlyContinue }
        else { Remove-Item -Path $p -ErrorAction SilentlyContinue }
    }
}

function global:ls {
    param([Parameter(ValueFromRemainingArguments=$true)]$args)
    $hasA = $false
    foreach ($a in $args) { if ($a -like '-*a*') { $hasA = $true } }
    if ($hasA) { Get-ChildItem -Force | Format-Table -AutoSize } 
    else { Get-ChildItem | Format-Table -AutoSize }
}
function global:ll { Get-ChildItem -Force | Format-Table -AutoSize }

function global:cp {
    param([Parameter(ValueFromRemainingArguments=$true)]$args)
    $paths = $args | Where-Object { $_ -notlike '-*' }
    $isRec = $false
    foreach ($a in $args) { if ($a -like '-*r*' -or $a -like '-*R*') { $isRec = $true } }
    if ($paths.Count -ge 2) {
        if ($isRec) { Copy-Item -Path $paths[0] -Destination $paths[1] -Recurse -Force }
        else { Copy-Item -Path $paths[0] -Destination $paths[1] -Force }
    }
}

function global:mv ($src, $dst) { Move-Item -Path $src -Destination $dst -Force }
function global:mkdir { param([Parameter(ValueFromRemainingArguments=$true)]$args) foreach ($p in ($args | Where-Object { $_ -notlike '-*' })) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }
function global:touch ($path) { New-Item -ItemType File -Path $path -Force | Out-Null }
function global:ln ($target, $link) { New-Item -ItemType SymbolicLink -Path $link -Value $target }
function global:chmod ($perms, $path) { icacls $path /grant "*S-1-1-0:($perms)" }
function global:chown ($owner, $path) { icacls $path /setowner $owner }
function global:du ($path='.') { Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | Select-Object @{N='Path';E={$path}}, @{N='Size(MB)';E={[math]::Round($_.Sum/1MB,2)}} | Format-Table -AutoSize }

function global:cat ($path) { Get-Content -Path $path }
function global:head ($path, [int]$n=10) { Get-Content -Path $path -Head $n }
function global:tail { param($path, [int]$n=10, [switch]$f) if ($f) { Get-Content -Path $path -Wait -Tail $n } else { Get-Content -Path $path -Tail $n } }
function global:grep { param($pattern, $path) if ($path) { Select-String -Pattern $pattern -Path $path } else { $input | Select-String -Pattern $pattern } }
function global:sed ($search, $replace, $path) { (Get-Content $path) -replace $search, $replace | Set-Content $path }
function global:awk ([int]$col=1) { $input | ForEach-Object { $fields = $_ -split '\s+'; if ($fields[$col-1]) { $fields[$col-1] } } }
function global:wc { param($path) if ($path) { $lines = (Get-Content $path).Count; $words = ((Get-Content $path) -join ' ' -split '\s+').Count; [PSCustomObject]@{Lines=$lines; Words=$words; Path=$path} | Format-Table -AutoSize } else { $lines = ($input).Count; [PSCustomObject]@{Lines=$lines} } }
function global:sort { $input | Sort-Object }
function global:uniq { $input | Select-Object -Unique }
function global:tee ($path) { $input | Tee-Object -FilePath $path }
function global:diff ($file1, $file2) { Compare-Object -ReferenceObject (Get-Content $file1) -DifferenceObject (Get-Content $file2) }
function global:find ($path='.', $filter='*') { Get-ChildItem -Path $path -Recurse -Filter $filter -ErrorAction SilentlyContinue }
function global:clear { Clear-Host }
function global:which ($cmd) { Get-Command -Name $cmd -ErrorAction SilentlyContinue }

function global:tar {
    param([Parameter(ValueFromRemainingArguments=$true)]$args)
    $opt = $args[0]; $archive = $args[1]; $target = $args[2]
    if ($opt -like '*x*') { Expand-Archive -Path $archive -DestinationPath . -Force }
    elseif ($opt -like '*c*') { Compress-Archive -Path $target -DestinationPath $archive -Force }
}
function global:zip ($archive, $target) { Compress-Archive -Path $target -DestinationPath $archive -Force }
function global:unzip ($archive, $dest='.') { Expand-Archive -Path $archive -DestinationPath $dest -Force }

function global:top { Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Id, ProcessName, @{N='CPU(s)';E={[math]::Round($_.CPU,2)}}, @{N='RAM(MB)';E={[math]::Round($_.WorkingSet64/1MB,2)}} | Format-Table -AutoSize }
function global:ps { Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet64 | Format-Table -AutoSize }
function global:free { Get-CimInstance Win32_OperatingSystem | Select-Object @{N='TotalRAM(MB)';E={[math]::Round($_.TotalVisibleMemorySize/1KB,2)}}, @{N='FreeRAM(MB)';E={[math]::Round($_.FreePhysicalMemory/1KB,2)}} | Format-Table -AutoSize }
function global:df { Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}, @{N='Free(GB)';E={[math]::Round($_.Free/1GB,2)}} | Format-Table -AutoSize }
function global:uptime { (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
function global:kill { param([int]$pid) Stop-Process -Id $pid -Force }
function global:killall ($name) { Stop-Process -Name $name -Force }

function global:curl { param($url, $out) if ($out) { Invoke-WebRequest -Uri $url -OutFile $out } else { (Invoke-WebRequest -Uri $url).Content } }
function global:wget ($url, $out) { if (!$out) { $out = Split-Path $url -Leaf }; (New-Object System.Net.WebClient).DownloadFile($url, $out) }
function global:ip ($cmd) { Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily | Format-Table -AutoSize }
function global:ifconfig { Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily | Format-Table -AutoSize }
function global:route { Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric | Format-Table -AutoSize }
function global:netstat { Get-NetTCPConnection | Where-Object State -eq 'Listen' | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize }
function global:nslookup ($domain) { Resolve-DnsName -Name $domain }
function global:dig ($domain) { Resolve-DnsName -Name $domain }
function global:ping ($host, [int]$c=4) { Test-Connection -ComputerName $host -Count $c }
function global:traceroute ($host) { Test-NetConnection -ComputerName $host -TraceRoute }
function global:nc ($host, [int]$port) { (Test-NetConnection -ComputerName $host -Port $port).TcpTestSucceeded }

function global:whoami { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
function global:id { [System.Security.Principal.WindowsIdentity]::GetCurrent() }
function global:sudo { param([Parameter(ValueFromRemainingArguments=$true)]$args) Start-Process powershell -Verb RunAs -ArgumentList "-Command $args" }

function global:systemctl ($action, $service) { 
    if ($action -eq 'status') { Get-Service -Name $service -ErrorAction SilentlyContinue } 
    elseif ($action -eq 'start') { Start-Service -Name $service } 
    elseif ($action -eq 'stop') { Stop-Service -Name $service } 
    elseif ($action -eq 'restart') { Restart-Service -Name $service } 
    else { Get-Service } 
}

function global:apt ($action, $package) {
    if ($action -eq 'update' -or $action -eq 'upgrade') {
        winget upgrade --all --source winget --accept-package-agreements --accept-source-agreements
    } elseif ($action -eq 'install') {
        winget install $package --source winget --accept-package-agreements --accept-source-agreements
    } elseif ($action -eq 'search') {
        winget search $package --source winget
    } else {
        winget list
    }
}

function global:export ($varVal) { $parts = $varVal -split '='; if ($parts.Count -eq 2) { [Environment]::SetEnvironmentVariable($parts[0], $parts[1]) } }
function global:reboot { Restart-Computer -Force }
function global:shutdown { Stop-Computer -Force }

Clear-Host
Write-Host '====================================================================' -ForegroundColor Cyan
Write-Host '  🚀 MASTER UNIVERSAL POSIX-TO-POWERSHELL TRANSLATION BRIDGE ACTIVE' -ForegroundColor Green
Write-Host '  => Full Parity Mapped: File Ops, Networking, Services, Packages, Metrics' -ForegroundColor Yellow
Write-Host '====================================================================' -ForegroundColor Cyan
`

	sftpClient, err := sftp.NewClient(client)
	if err == nil {
		defer sftpClient.Close()
		f, err := sftpClient.Create(remoteProfilePath)
		if err == nil {
			_, _ = f.Write([]byte(profileScript))
			_ = f.Close()
		}
	}

	return fmt.Sprintf(`powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "%s"`, remoteProfilePath)
}

func isDefaultTag(isDef bool) string {
	if isDef {
		return Green + "[DEFAULT / RECOMMENDED]" + Reset
	}
	return ""
}