package rbac

// windows_parity.go
// Windows-native equivalents of the Linux/iptables/sudoers features in rbac.go.
// Requires the helpers added by patch_rbac_windows.py (psExec, execRemote, psPrefix, psEncode).
//
// How each Linux feature maps to Windows:
//   iptables --uid-owner ACCEPT/DROP  ->  Windows Firewall rules bound to the user's SID (-LocalUser).
//                                         Windows evaluates BLOCK before ALLOW, so the tool keeps a small
//                                         state file per user and REBUILDS the block rules (allowed ports
//                                         are carved out of the block range) to give Linux-identical behavior.
//   sudoers RBAC tiers                ->  Built-in local groups (least privilege). Windows has no per-command
//                                         sudo whitelist over SSH, so tiers map to the closest OS groups.
//   /etc/cross_*.txt registries       ->  %ProgramData%\CrossSuite\*.txt (ACL: Administrators/SYSTEM write only)
//   ip addr add / ip addr del         ->  New-NetIPAddress / Remove-NetIPAddress (ActiveStore, like `ip addr add`)
//   pkill -9 -u                       ->  Get-Process -IncludeUserName | Stop-Process
//   userdel -r                        ->  Remove-LocalUser + Win32_UserProfile removal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"cross-ssh/pkg/common"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------
//  small PowerShell building blocks
// ---------------------------------------------------------------------

func psq(s string) string { return strings.ReplaceAll(s, "'", "''") }

// psBuildCommand turns a script into a one-line command. cmd.exe caps a command line at 8191 chars, so
// long scripts are gzip-compressed and unpacked by a tiny PowerShell stub on the target.
func psBuildCommand(script string) string {
	const head = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
	if enc := psEncode(script); len(enc) <= 6000 {
		return head + enc
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(script))
	_ = zw.Close()
	stub := "$b = [Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(buf.Bytes()) + "'); " +
		"$m = New-Object IO.MemoryStream(,$b); $g = New-Object IO.Compression.GzipStream($m, [IO.Compression.CompressionMode]::Decompress); " +
		"$r = New-Object IO.StreamReader($g, [Text.Encoding]::UTF8); Invoke-Expression $r.ReadToEnd()"
	return head + psEncode(stub)
}

// state dir, created + locked down (writes = Administrators/SYSTEM only)
const psStateInit = `$D = Join-Path $env:ProgramData 'CrossSuite'; if(-not (Test-Path $D)){ New-Item -ItemType Directory -Force -Path $D | Out-Null; icacls $D /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null }; `

// state dir path only (read-only scripts)
const psStateRead = `$D = Join-Path $env:ProgramData 'CrossSuite'; `

func psKVSet(file, key, val string) string {
	return fmt.Sprintf(`$f = Join-Path $D '%s'; $k = @(); if(Test-Path $f){ $k = @(Get-Content $f | Where-Object { $_ -and ($_ -notlike '%s:*') }) }; $k += '%s:%s'; Set-Content -Path $f -Value $k; `,
		file, psq(key), psq(key), psq(val))
}

func psKVDel(file, key string) string {
	return fmt.Sprintf(`$f = Join-Path $D '%s'; if(Test-Path $f){ $k = @(Get-Content $f | Where-Object { $_ -and ($_ -notlike '%s:*') }); if($k.Count -gt 0){ Set-Content -Path $f -Value $k } else { Remove-Item -Path $f -ErrorAction SilentlyContinue } }; `,
		file, psq(key))
}

// psKVGet loads the value for key into PowerShell variable $varName (” when absent)
func psKVGet(file, key, varName string) string {
	return fmt.Sprintf(`$f = Join-Path $D '%s'; $%s = ''; if(Test-Path $f){ $l = Get-Content $f | Where-Object { $_ -like '%s:*' } | Select-Object -First 1; if($l){ $%s = $l.Substring(%d) } }; `,
		file, varName, psq(key), varName, len(key)+1)
}

func winCmdFrom(script string) string { return psPrefix + script + `"` }

// ---------------------------------------------------------------------
//  [8]/[7]/[9] user listing
// ---------------------------------------------------------------------

func winFetchUsers(client *ssh.Client, sig HostSignature) []UserSummary {
	script := psStateRead + `
function KV($n){ $h=@{}; $f=Join-Path $D $n; if(Test-Path $f){ Get-Content $f | ForEach-Object { $i=$_.IndexOf(':'); if($i -gt 0){ $h[$_.Substring(0,$i)]=$_.Substring($i+1) } } }; $h };
$ips=KV 'ips.txt'; $tiers=KV 'tiers.txt'; $tool=KV 'users.txt';
$admins=@(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Split('\')[-1] });
$active=@(); try { $active=@(quser 2>$null | Select-Object -Skip 1 | ForEach-Object { ($_.ToString() -replace '^[> ]+','' -split '\s+')[0] }) } catch {};
$geo='Local'; try { $g=Invoke-RestMethod -Uri 'http://ip-api.com/json/?fields=city,countryCode' -TimeoutSec 2; $x=(($g.city + ', ' + $g.countryCode).Trim(', ')); if($x){ $geo=$x } } catch {};
$pip=(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1 -ExpandProperty IPAddress);
Get-LocalUser | Where-Object { @('DefaultAccount','WDAGUtilityAccount','Guest') -notcontains $_.Name } | ForEach-Object {
  $n=$_.Name;
  if($admins -contains $n){ $t='Super-Admin' } elseif($tiers.ContainsKey($n)){ $t=$tiers[$n] } else { $t='Standard User' };
  if(-not $_.Enabled){ $s='LOCKED' } elseif($active -contains $n){ $s='ACTIVE' } else { $s='INACTIVE' };
  if($ips.ContainsKey($n)){ $ip=$ips[$n] } elseif($_.SID.Value -like '*-500'){ $ip=$pip } else { $ip='Unassigned' };
  if($tool.ContainsKey($n)){ $o='TOOL' } else { $o='SYSTEM' };
  $n + '|' + $_.SID.Value + '|' + $ip + '|' + $geo + '|powershell|' + $s + '|' + $t + '|' + $o
}`
	out, _ := psExec(client, script)
	var users []UserSummary
	idx := 1
	for _, l := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimSpace(l), "|")
		if len(parts) >= 8 {
			users = append(users, UserSummary{
				Index: idx, Username: parts[0], UID: parts[1], AssignedIP: parts[2],
				GeoLocation: parts[3], Shell: parts[4], Status: parts[5], RBACTier: parts[6],
				IsTool: parts[7] == "TOOL", HostAlias: currentHostAlias,
			})
			idx++
		}
	}
	return users
}

// ---------------------------------------------------------------------
//  [10] Port access + [5] confinement  (Windows Firewall state engine)
// ---------------------------------------------------------------------

func fwAdd(line string) string {
	return fmt.Sprintf(`$st = @($st | Where-Object { $_ -ne '%s' }) + '%s'`, psq(line), psq(line))
}
func fwRm(line string) string {
	return fmt.Sprintf(`$st = @($st | Where-Object { $_ -ne '%s' })`, psq(line))
}
func fwRmLike(pat string) string {
	return fmt.Sprintf(`$st = @($st | Where-Object { $_ -notlike '%s' })`, psq(pat))
}

// rebuilds every cross_<user>_* firewall rule from the state list ($st)
const winFwApply = `$sid = (New-Object System.Security.Principal.NTAccount($u)).Translate([System.Security.Principal.SecurityIdentifier]).Value; $lu = 'D:(A;;CC;;;' + $sid + ')'; ` +
	`Get-NetFirewallRule -DisplayName ('cross_' + $u + '_*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; ` +
	`if(-not ($st -contains 'allowall:1')){ ` +
	`$ports = @($st | Where-Object { $_ -like 'port:*' } | ForEach-Object { [int]$_.Substring(5) } | Sort-Object -Unique); ` +
	`$ranges = @(); $prev = 0; foreach($p in $ports){ if($p -gt ($prev + 1)){ $ranges += ('{0}-{1}' -f ($prev + 1), ($p - 1)) }; $prev = $p }; if($ports.Count -gt 0 -and $prev -lt 65535){ $ranges += ('{0}-65535' -f ($prev + 1)) }; ` +
	`$pols = @($st | Where-Object { $_ -like 'policy:*' } | ForEach-Object { $_.Substring(7) }); if($pols.Count -eq 0 -and $ports.Count -gt 0){ $pols = @('total') }; ` +
	`foreach($pol in $pols){ ` +
	`if($pol -eq 'lan'){ $addr = @('192.168.0.0/16','10.0.0.0/8','172.16.0.0/12','169.254.0.0/16') } ` +
	`elseif($pol -eq 'wan'){ $addr = @('1.0.0.0-9.255.255.255','11.0.0.0-126.255.255.255','128.0.0.0-169.253.255.255','169.255.0.0-172.15.255.255','172.32.0.0-192.167.255.255','192.169.0.0-223.255.255.255') } ` +
	`else { $addr = @('Any') }; ` +
	`$n = 'cross_' + $u + '_' + $pol; ` +
	`if($ports.Count -eq 0){ New-NetFirewallRule -DisplayName ($n + '_all') -Direction Outbound -Action Block -Protocol Any -RemoteAddress $addr -LocalUser $lu | Out-Null } ` +
	`else { ` +
	`New-NetFirewallRule -DisplayName ($n + '_tcp') -Direction Outbound -Action Block -Protocol TCP -RemotePort $ranges -RemoteAddress $addr -LocalUser $lu | Out-Null; ` +
	`New-NetFirewallRule -DisplayName ($n + '_udp') -Direction Outbound -Action Block -Protocol UDP -RemotePort $ranges -RemoteAddress $addr -LocalUser $lu | Out-Null ` +
	`} } }`

func winFwScript(user string, ops []string) string {
	var b strings.Builder
	b.WriteString(psStateInit)
	fmt.Fprintf(&b, `$u = '%s'; $f = Join-Path $D ('fw_' + $u + '.txt'); $st = @(); if(Test-Path $f){ $st = @(Get-Content $f | Where-Object { $_ }) }; `, psq(user))
	for _, o := range ops {
		b.WriteString(o)
		b.WriteString("; ")
	}
	b.WriteString(`if($st.Count -gt 0){ Set-Content -Path $f -Value $st } else { Remove-Item -Path $f -ErrorAction SilentlyContinue }; `)
	b.WriteString(winFwApply)
	return b.String()
}

func winAllowedPorts(client *ssh.Client, user string) []string {
	script := psStateRead + fmt.Sprintf(`$f = Join-Path $D ('fw_' + '%s' + '.txt'); if(Test-Path $f){ $s = @(Get-Content $f); $o = @($s | Where-Object { $_ -like 'port:*' } | ForEach-Object { $_.Substring(5) }); if($s -contains 'allowall:1'){ $o += 'ALL-PORTS' }; $o -join ',' }`, psq(user))
	out, _ := psExec(client, script)
	var res []string
	for _, p := range strings.Split(strings.TrimSpace(out), ",") {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

func winApplyPortRule(client *ssh.Client, username, port, action string) {
	var ops []string
	switch action {
	case "add":
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			fmt.Println(common.Red + "[!] Port must be 1-65535." + common.Reset)
			return
		}
		ops = []string{fwAdd("port:" + strconv.Itoa(n))}
	case "add-all":
		ops = []string{fwAdd("allowall:1")}
	case "remove":
		ops = []string{fwRm("port:" + port)}
	case "remove-blanket":
		ops = []string{fwRm("allowall:1")}
	case "remove-all":
		ops = []string{fwRmLike("port:*"), fwRm("allowall:1")}
	default:
		return
	}
	if _, err := psExec(client, winFwScript(username, ops)); err != nil {
		return
	}
	switch action {
	case "add":
		fmt.Printf(common.Green+"[✔] Port %s allowed for user %s.\n"+common.Reset, port, username)
	case "add-all":
		fmt.Printf(common.Green+"[✔] ALL traffic allowed for user %s.\n"+common.Reset, username)
	case "remove":
		fmt.Printf(common.Green+"[✔] Port %s rule removed for user %s.\n"+common.Reset, port, username)
	case "remove-blanket":
		fmt.Printf(common.Green+"[✔] Blanket Allow-All rule removed for user %s.\n"+common.Reset, username)
	case "remove-all":
		fmt.Printf(common.Green+"[✔] ALL port rules removed for user %s.\n"+common.Reset, username)
	}
}

const lanAddrPS = `@('192.168.0.0/16','10.0.0.0/8','172.16.0.0/12','169.254.0.0/16')`
const wanAddrPS = `@('1.0.0.0-9.255.255.255','11.0.0.0-126.255.255.255','128.0.0.0-169.253.255.255','169.255.0.0-172.15.255.255','172.32.0.0-192.167.255.255','192.169.0.0-223.255.255.255')`

// winIcmpHostWide is scoped per-policy: policy = "lan", "wan", or "total".
// Note: -LocalUser is still impossible for ICMP (WFP limitation), so this
// still affects ALL users on the machine — but it now respects which
// destinations (LAN-only / WAN-only / everywhere) the policy meant.
func winIcmpHostWide(client *ssh.Client, policy string, enable bool) {
	n4 := "cross_icmp_" + policy + "4"
	n6 := "cross_icmp_" + policy + "6"
	s := fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; `, n4)
	s += fmt.Sprintf(`Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; `, n6)
	if enable {
		if policy == "lan" {
			s += fmt.Sprintf(`New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -Protocol ICMPv4 -RemoteAddress %s -ErrorAction Stop | Out-Null; `, n4, lanAddrPS)
		} else if policy == "wan" {
			s += fmt.Sprintf(`New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -Protocol ICMPv4 -RemoteAddress %s -ErrorAction Stop | Out-Null; `, n4, wanAddrPS)
		} else {
			s += fmt.Sprintf(`New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -Protocol ICMPv4 -ErrorAction Stop | Out-Null; `, n4)
		}
		if policy == "total" {
			s += fmt.Sprintf(`New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -Protocol ICMPv6 -ErrorAction Stop | Out-Null; `, n6)
		}
	}
	if _, err := psExec(client, psStateInit+s); err != nil {
		fmt.Println(common.Red + "[!] Failed to apply ICMP rule: " + err.Error() + common.Reset)
	}
}

func winConfinement(reader *bufio.Reader, client *ssh.Client, username string) {
	if strings.EqualFold(username, "Administrator") {
		fmt.Println(common.Red + "[!] Protected account." + common.Reset)
		common.PausePrompt()
		return
	}
	if out, err := psExec(client, `$env:USERNAME`); err == nil && strings.EqualFold(strings.TrimSpace(out), username) {
		fmt.Println(common.Red + common.Bold + "[!] Refusing: this is the SAME account your SSH management session is authenticated as." + common.Reset)
		fmt.Println(common.Yellow + "    Confining WAN/LAN/Total for this account could sever your own control session and lock you out." + common.Reset)
		fmt.Println(common.Yellow + "    Log in via SSH as a different admin account to confine this one." + common.Reset)
		common.PausePrompt()
		return
	}
	if out, err := psExec(client, `(Get-NetFirewallProfile -Name Private).Enabled.ToString() + ',' + (Get-NetFirewallProfile -Name Public).Enabled.ToString() + ',' + (Get-NetFirewallProfile -Name Domain).Enabled.ToString()`); err == nil {
		parts := strings.Split(strings.TrimSpace(out), ",")
		if len(parts) == 3 && (parts[0] == "False" || parts[1] == "False" || parts[2] == "False") {
			fmt.Println(common.Red + common.Bold + "[!] WARNING: One or more Windows Firewall profiles are DISABLED (Private/Public/Domain)." + common.Reset)
			fmt.Println(common.Yellow + "    Confinement rules will be created but WILL NOT be enforced until all profiles are enabled." + common.Reset)
			fmt.Print(common.Yellow + "    Enable all firewall profiles now? (y/N): " + common.Reset)
			ans, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(ans)) == "y" {
				if _, e := psExec(client, `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True`); e == nil {
					fmt.Println(common.Green + "    ✔ All firewall profiles enabled." + common.Reset)
				} else {
					fmt.Println(common.Red + "    Failed to enable profiles: " + e.Error() + common.Reset)
				}
			}
		}
	}
	fmt.Printf("\nSelected User: [%s]\n", username)
	fmt.Println("Select Confinement Policy:")
	fmt.Println("  [1] Block Local Private LAN Subnets (Prevent lateral network traversal)")
	fmt.Println("  [2] Blackhole External Internet Access (Block WAN / Egress completely)")
	fmt.Println("  [3] Complete Network Blackhole (Block ALL outbound traffic for this user)")
	fmt.Println(common.Green + "  [4] Granular Unblock & Restore Engine (Select what to unblock)" + common.Reset)
	fmt.Println("  [0] Cancel")
	fmt.Print("Select Policy [0-4]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	run := func(ops []string, ok string) {
		if _, err := psExec(client, winFwScript(username, ops)); err == nil {
			fmt.Printf(common.Green+ok+common.Reset, username)
		}
	}

	askIcmp := func(policy string) {
		fmt.Print(common.Yellow + "Also block ICMP/ping for this scope? Windows cannot scope ICMP per-user, so this affects the WHOLE machine (every user), but only for " + policy + " destinations. (y/N): " + common.Reset)
		icmpAns, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(icmpAns)) == "y" {
			winIcmpHostWide(client, policy, true)
			fmt.Println(common.Green + "   ICMP blocked for " + policy + " scope (host-wide, all users)." + common.Reset)
		} else {
			fmt.Println(common.Yellow + "   Skipped — ping will keep working even though TCP/UDP is now blocked. This is expected." + common.Reset)
		}
	}

	switch choice {
	case "1":
		run([]string{fwRmLike("policy:*"), fwAdd("policy:lan")}, "✅ Success: Local LAN access is now blocked for user [%s]!\n")
		askIcmp("lan")
	case "2":
		run([]string{fwRmLike("policy:*"), fwAdd("policy:wan")}, "✅ Success: External internet access is now blackholed for user [%s]!\n")
		askIcmp("wan")
	case "3":
		run([]string{fwRmLike("policy:*"), fwRmLike("port:*"), fwRm("allowall:1"), fwAdd("policy:total")},
			"✅ Success: COMPLETE NETWORK BLACKHOLE enforced for user [%s]! (all outbound traffic blocked)\n")
		askIcmp("total")
	case "4":
		activePolicies := []string{}
		if out, err := psExec(client, psStateRead+fmt.Sprintf(`$f = Join-Path $D ('fw_' + '%s' + '.txt'); if(Test-Path $f){ (Get-Content $f | Where-Object { $_ -like 'policy:*' }) -join ',' }`, psq(username))); err == nil {
			for _, p := range strings.Split(strings.TrimSpace(out), ",") {
				if p = strings.TrimSpace(p); p != "" {
					activePolicies = append(activePolicies, strings.TrimPrefix(p, "policy:"))
				}
			}
		}
		fmt.Printf("\n--- GRANULAR UNBLOCK ENGINE FOR [%s] ---\n", username)
		if len(activePolicies) == 0 {
			fmt.Println(common.Yellow + "  (No confinement policy currently active for this user.)" + common.Reset)
		} else {
			fmt.Println(common.Cyan + "  Currently active: " + strings.Join(activePolicies, ", ") + common.Reset)
		}
		fmt.Println("  [1] Unblock Local LAN Only")
		fmt.Println("  [2] Unblock External Internet Only")
		fmt.Println("  [3] Lift Complete Network Blackhole")
		fmt.Println(common.Green + "  [4] Clean Full Reset (Remove ALL firewall blocks for this user)" + common.Reset)
		fmt.Println("  [0] Cancel")
		fmt.Print("Select Unblock Action [0-4]: ")
		u, _ := reader.ReadString('\n')
		u = strings.TrimSpace(u)
		var ops []string
		var targetPolicy string
		switch u {
		case "1":
			targetPolicy, ops = "lan", []string{fwRm("policy:lan")}
		case "2":
			targetPolicy, ops = "wan", []string{fwRm("policy:wan")}
		case "3":
			targetPolicy, ops = "total", []string{fwRm("policy:total")}
		case "4":
			ops = []string{fwRmLike("policy:*"), fwRmLike("port:*"), fwRm("allowall:1")}
			winIcmpHostWide(client, "lan", false)
			winIcmpHostWide(client, "wan", false)
			winIcmpHostWide(client, "total", false)
			run(ops, "✅ Success: Selected network confinement rules cleanly unblocked for user [%s]!\n")
			return
		default:
			return
		}
		matched := false
		for _, p := range activePolicies {
			if p == targetPolicy {
				matched = true
				break
			}
		}
		if !matched {
			fmt.Println(common.Red + "[!] No active '" + targetPolicy + "' policy found for this user — nothing to lift." + common.Reset)
			if len(activePolicies) > 0 {
				fmt.Println(common.Yellow + "    Active policy is actually: " + strings.Join(activePolicies, ", ") + " — pick the matching option, or use [4] Clean Full Reset." + common.Reset)
			}
			common.PausePrompt()
			return
		}
		winIcmpHostWide(client, targetPolicy, false)
		run(ops, "✅ Success: Selected network confinement rules cleanly unblocked for user [%s]!\n")
	default:
		return
	}
	common.PausePrompt()
}

// ---------------------------------------------------------------------
//  [2] RBAC tiers -> Windows local groups
// ---------------------------------------------------------------------

var winTierGroups = map[string][]string{
	"Super-Admin": {"@ADMIN"},
	"DevOps Eng":  {"Remote Management Users", "Network Configuration Operators", "Performance Log Users", "Performance Monitor Users", "docker-users", "Hyper-V Administrators"},
	"Sec Auditor": {"Event Log Readers", "Performance Monitor Users"},
	"DB Admin":    {"Performance Monitor Users", "@SQL"},
}

func psList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = "'" + psq(s) + "'"
	}
	return "@(" + strings.Join(q, ",") + ")"
}

func winTierScript(user, tier string, want []string) string {
	// every group any tier can grant (used to strip the previous tier first)
	seen := map[string]bool{}
	var union []string
	for _, gs := range winTierGroups {
		for _, g := range gs {
			if !strings.HasPrefix(g, "@") && !seen[g] {
				seen[g] = true
				union = append(union, g)
			}
		}
	}
	var b strings.Builder
	b.WriteString(psStateInit)
	fmt.Fprintf(&b, `$u = '%s'; $tier = '%s'; `, psq(user), psq(tier))
	b.WriteString(`$adm = (Get-LocalGroup -SID 'S-1-5-32-544').Name; `)
	b.WriteString(`if($tier -ne 'Super-Admin' -and $u -eq $env:USERNAME){ throw 'Refusing to change the privileges of the account this session is logged in with.' }; `)
	b.WriteString(psKVGet("groups.txt", user, "old"))
	fmt.Fprintf(&b, `$rev = @($adm) + %s + @(Get-LocalGroup | Where-Object { $_.Name -like '*SQL*' } | ForEach-Object { $_.Name }) + @($old -split ',' | Where-Object { $_ }); `, psList(union))
	b.WriteString(`foreach($g in ($rev | Sort-Object -Unique)){ Remove-LocalGroupMember -Group $g -Member $u -ErrorAction SilentlyContinue }; `)
	// resolve wanted groups
	var lit []string
	for _, g := range want {
		switch g {
		case "@ADMIN":
			lit = append(lit, "$adm")
		case "@SQL":
			lit = append(lit, "@(Get-LocalGroup | Where-Object { $_.Name -like '*SQL*' } | ForEach-Object { $_.Name })")
		default:
			lit = append(lit, "'"+psq(g)+"'")
		}
	}
	fmt.Fprintf(&b, `$want = @(%s); `, strings.Join(lit, ","))
	b.WriteString(`$ok = @(); $miss = @(); foreach($g in $want){ if(Get-LocalGroup -Name $g -ErrorAction SilentlyContinue){ Add-LocalGroupMember -Group $g -Member $u -ErrorAction SilentlyContinue; if(Get-LocalGroupMember -Group $g -Member $u -ErrorAction SilentlyContinue){ $ok += $g } else { throw ('Could not add to group ' + $g + ' (access denied - is the SSH session elevated?)') } } else { $miss += $g } }; `)
	if tier == "" { // revoke
		b.WriteString(psKVDel("tiers.txt", user))
		b.WriteString(psKVDel("groups.txt", user))
	} else {
		b.WriteString(psKVSet("tiers.txt", user, tier))
		if tier == "Custom Whitelist" {
			b.WriteString(psKVSet("groups.txt", user, strings.Join(want, ",")))
		} else {
			b.WriteString(psKVDel("groups.txt", user))
		}
	}
	b.WriteString(`Write-Output ('ADDED=' + ($ok -join ',') + ';MISSING=' + ($miss -join ','))`)
	return b.String()
}

func winApplyTier(reader *bufio.Reader, client *ssh.Client, username, choice string) {
	var tier string
	var want []string
	switch choice {
	case "1":
		tier = "Super-Admin"
	case "2":
		tier = "DevOps Eng"
	case "3":
		tier = "Sec Auditor"
	case "4":
		tier = "DB Admin"
	case "5":
		fmt.Print("Enter comma-separated local group names to grant (e.g. Remote Management Users, Event Log Readers): ")
		in, _ := reader.ReadString('\n')
		for _, g := range strings.Split(in, ",") {
			if g = strings.TrimSpace(g); g != "" {
				want = append(want, g)
			}
		}
		if len(want) == 0 {
			fmt.Println(common.Yellow + "[!] No groups provided. Operation cancelled." + common.Reset)
			return
		}
		tier = "Custom Whitelist"
	case "6":
		tier = ""
	default:
		fmt.Println(common.Yellow + "[!] Invalid choice." + common.Reset)
		return
	}
	if want == nil {
		want = winTierGroups[tier]
	}
	fmt.Println(common.Cyan + "[+] Applying RBAC tier via Windows local groups..." + common.Reset)
	out, err := psExec(client, winTierScript(username, tier, want))
	if err != nil {
		return
	}
	if tier == "" {
		fmt.Println(common.Green + "✅ All elevated privileges revoked for user [" + username + "]!" + common.Reset)
		return
	}
	fmt.Printf(common.Green+"✅ Success: User [%s] elevated to Tier [%s]!\n"+common.Reset, username, tier)
	if i := strings.Index(out, "ADDED="); i >= 0 {
		fmt.Println(common.Cyan + "   " + strings.TrimSpace(out[i:]) + common.Reset)
	}
	if strings.Contains(out, "MISSING=") && !strings.Contains(out, "MISSING=\n") && !strings.HasSuffix(strings.TrimSpace(out), "MISSING=") {
		fmt.Println(common.Yellow + "   (Groups listed as MISSING do not exist on this Windows edition/host and were skipped.)" + common.Reset)
	}
	fmt.Println(common.Yellow + "   Note: Windows has no per-command sudo whitelist over SSH; tiers map to OS local groups." + common.Reset)
}

// ---------------------------------------------------------------------
//  [3] IP stacking
// ---------------------------------------------------------------------

func winIPPurgeSnippet(user string) string {
	return psKVGet("ips.txt", user, "ipc") +
		`if($ipc){ Get-NetIPAddress -IPAddress ($ipc.Split('/')[0]) -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }; ` +
		psKVDel("ips.txt", user) +
		fmt.Sprintf(`Unregister-ScheduledTask -TaskName 'cross_ip_%s' -Confirm:$false -ErrorAction SilentlyContinue; `, psq(user))
}

func winIPAssignSnippet(iface, cidr, user string, ttlMin int) string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ones, _ := ipnet.Mask.Size()
	s := fmt.Sprintf(`$ip = '%[1]s'; $already = [bool](Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue); if($already){ throw ('IP ' + $ip + ' already exists on this host - refusing to register a pre-existing address as a tool-managed stacked IP (this would make Purge delete it later).') }; $origDhcp = (Get-NetIPInterface -InterfaceAlias '%[2]s' -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp; try { New-NetIPAddress -InterfaceAlias '%[2]s' -IPAddress $ip -PrefixLength %[3]d -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; if($origDhcp -eq 'Enabled'){ Set-NetIPInterface -InterfaceAlias '%[2]s' -Dhcp Enabled -ErrorAction SilentlyContinue }; } catch { if($origDhcp -eq 'Enabled'){ Set-NetIPInterface -InterfaceAlias '%[2]s' -Dhcp Enabled -ErrorAction SilentlyContinue; ipconfig /renew | Out-Null }; throw }; `,
		ip.String(), psq(iface), ones)
	s += psKVSet("ips.txt", user, cidr)
	if ttlMin > 0 {
		payload := psStateRead + winIPPurgeSnippet(user)
		s += fmt.Sprintf(`$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -EncodedCommand %s'; $t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(%d); Register-ScheduledTask -TaskName 'cross_ip_%s' -Action $a -Trigger $t -User 'SYSTEM' -RunLevel Highest -Force | Out-Null; `,
			psEncode(payload), ttlMin, psq(user))
	}
	return s
}

func winIPStack(reader *bufio.Reader, client *ssh.Client, username string, ifaces []NetworkInterface, mode string) {
	if mode == "3" {
		if _, err := psExec(client, psStateInit+winIPPurgeSnippet(username)); err == nil {
			fmt.Printf(common.Green+"✅ Success: Assigned IP address for user [%s] has been unbound and purged!\n"+common.Reset, username)
		}
		common.PausePrompt()
		return
	}
	fmt.Println("\nAvailable Network Interfaces on Remote Host:")
	for i, iface := range ifaces {
		fmt.Printf("  [%d] %-12s (Current IP: %s)\n", i+1, iface.Name, iface.IP)
	}
	fmt.Printf("Select Adapter to Stack IP [1-%d]: ", len(ifaces))
	c, _ := reader.ReadString('\n')
	idx, err := strconv.Atoi(strings.TrimSpace(c))
	if err != nil || idx < 1 || idx > len(ifaces) {
		fmt.Println(common.Yellow + "[!] Invalid interface selected." + common.Reset)
		common.PausePrompt()
		return
	}
	iface := ifaces[idx-1].Name

	fmt.Print("\nEnter Dedicated Secondary IP to Stack (e.g. 192.168.0.210/24): ")
	in, _ := reader.ReadString('\n')
	cidr := strings.TrimSpace(in)
	if !strings.Contains(cidr, "/") {
		cidr += "/24"
	}
	if _, _, perr := net.ParseCIDR(cidr); perr != nil {
		fmt.Println(common.Red + "[!] Invalid IP address or CIDR format." + common.Reset)
		common.PausePrompt()
		return
	}
	ttl := 0
	if mode == "2" {
		fmt.Print("Enter Active Duration in Minutes (e.g. 30 for 30 mins, 480 for 8 hrs): ")
		t, _ := reader.ReadString('\n')
		ttl, _ = strconv.Atoi(strings.TrimSpace(t))
		if ttl <= 0 {
			ttl = 60
		}
	}
	fmt.Println(common.Cyan + "[+] Stacking pingable IP onto adapter and updating registry..." + common.Reset)
	if _, err := psExec(client, psStateInit+winIPAssignSnippet(iface, cidr, username, ttl)); err != nil {
		common.PausePrompt()
		return
	}
	if ttl > 0 {
		fmt.Printf(common.Green+"✅ Success: Ephemeral Pingable IP [%s] stacked for user [%s] on [%s] (TTL: %d minutes)!\n"+common.Reset, cidr, username, iface, ttl)
	} else {
		fmt.Printf(common.Green+"✅ Success: Permanent-until-reboot Pingable IP [%s] stacked for user [%s] on [%s]!\n"+common.Reset, cidr, username, iface)
	}
	fmt.Println(common.Yellow + "=> You can now ping this IP from any computer on the subnet (like `ip addr add`, it does not survive a reboot)." + common.Reset)
	common.PausePrompt()
}

// appended to the Windows provisioning script: registers the user with the tool (+ optional dedicated IP)
func winProvisionExtras(user, cidr, iface string) string {
	s := "; " + psStateInit + psKVSet("users.txt", user, "1")
	if cidr != "" && iface != "" {
		s += winIPAssignSnippet(iface, cidr, user, 0)
	}
	return s
}

// ---------------------------------------------------------------------
//  [6] host network orchestrator
// ---------------------------------------------------------------------

func winOrchestrate(client *ssh.Client, iface, newIP, newGW, newDNS, newHost string) {
	var b strings.Builder
	if newHost != "" {
		fmt.Fprintf(&b, `Rename-Computer -NewName '%s' -Force -ErrorAction Stop; `, psq(newHost))
	}
	if newIP != "" {
		if !strings.Contains(newIP, "/") {
			newIP += "/24"
		}
		ip, ipnet, err := net.ParseCIDR(newIP)
		if err != nil {
			fmt.Println(common.Red + "[!] Invalid IP/CIDR." + common.Reset)
			return
		}
		ones, _ := ipnet.Mask.Size()
		ifaceQ := psq(iface)
		ipStr := ip.String()
		fmt.Fprintf(&b, `$origAddrs = @(Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '%s' }); `, ifaceQ, ipStr)
		fmt.Fprintf(&b, `$origDhcp = (Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp; `, ifaceQ)
		fmt.Fprintf(&b, `try { `)
		fmt.Fprintf(&b, `$origAddrs | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; `)
		fmt.Fprintf(&b, `New-NetIPAddress -InterfaceAlias '%s' -IPAddress '%s' -PrefixLength %d -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; `, ifaceQ, ipStr, ones)
		fmt.Fprintf(&b, `} catch { `)
		fmt.Fprintf(&b, `if($origDhcp -eq 'Enabled'){ Set-NetIPInterface -InterfaceAlias '%s' -Dhcp Enabled -ErrorAction SilentlyContinue; ipconfig /renew | Out-Null } `, ifaceQ)
		fmt.Fprintf(&b, `else { foreach($a in $origAddrs){ New-NetIPAddress -InterfaceAlias '%s' -IPAddress $a.IPAddress -PrefixLength $a.PrefixLength -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null } } `, ifaceQ)
		fmt.Fprintf(&b, `throw ('Failed to change IP on %s, previous network configuration was automatically restored: ' + $_.Exception.Message) `, ifaceQ)
		fmt.Fprintf(&b, `}; `)
	}
	if newGW != "" {
		fmt.Fprintf(&b, `Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -Confirm:$false -ErrorAction SilentlyContinue; New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -NextHop '%s' -ErrorAction Stop | Out-Null; `,
			psq(iface), psq(iface), psq(newGW))
	}
	if newDNS != "" {
		fmt.Fprintf(&b, `Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses @('%s','1.0.0.1') -ErrorAction Stop; `, psq(iface), psq(newDNS))
	}
	if b.Len() == 0 {
		fmt.Println(common.Yellow + "[!] Nothing to change." + common.Reset)
		return
	}
	fmt.Println(common.Cyan + "[+] Applying network configuration changes..." + common.Reset)
	if _, err := psExec(client, b.String()); err != nil {
		return
	}
	fmt.Println(common.Green + "✅ Host Network Parameters successfully updated and applied!" + common.Reset)
	if newHost != "" {
		fmt.Printf("=> Hostname changed to: %s (Windows applies a rename after a reboot)\n", newHost)
	}
	if newIP != "" {
		fmt.Printf("=> Interface %s assigned: %s\n", iface, newIP)
	}
}

// ---------------------------------------------------------------------
//  [7] sessions / [9] quarantine, purge, nuke, dry-run
// ---------------------------------------------------------------------

func winKillUserScript(user string) string {
	q := psq(user)
	return fmt.Sprintf(
		`$prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'; `+
			`$sessLines = @(quser '%s' *>&1 | Out-String -Stream); `+
			`foreach($l in $sessLines){ if($l -match '\s(\d+)\s+(Active|Disc\w*)') { logoff $Matches[1] /server:localhost *>&1 | Out-Null } }; `+
			`$ErrorActionPreference = $prevEAP; `+
			`Start-Sleep -Milliseconds 500; `+
			`Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -and ($_.UserName.Split('\')[-1] -eq '%s') } | Stop-Process -Force -ErrorAction SilentlyContinue; `,
		q, q)
}

func winKillUserCmd(user string) string { return winCmdFrom(winKillUserScript(user)) }

func winLockUserCmd(user string) string {
	return winCmdFrom(winKillUserScript(user) + fmt.Sprintf(`Disable-LocalUser -Name '%[1]s' -ErrorAction Stop; if((Get-LocalUser -Name '%[1]s').Enabled){ throw 'Account is still enabled after Disable-LocalUser' }`, psq(user)))
}

// quarantine = kill + lock + strip admin/tier rights (Linux: passwd -l, pkill, remove sudoers)
func winQuarantineCmd(user string) string {
	return winCmdFrom(psStateInit + winKillUserScript(user) +
		fmt.Sprintf(`Disable-LocalUser -Name '%s' -ErrorAction Stop; $adm = (Get-LocalGroup -SID 'S-1-5-32-544').Name; Remove-LocalGroupMember -Group $adm -Member '%s' -ErrorAction SilentlyContinue; `, psq(user), psq(user)) +
		psKVDel("tiers.txt", user))
}

func winPurgeScript(user string) string {
	q := psq(user)
	return psStateInit + winKillUserScript(user) +
		fmt.Sprintf(`$sid = ''; try { $sid = (Get-LocalUser -Name '%s' -ErrorAction Stop).SID.Value } catch {}; if($sid){ Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Remove-CimInstance -ErrorAction SilentlyContinue }; `, q) +
		winIPPurgeSnippet(user) +
		fmt.Sprintf(`Get-NetFirewallRule -DisplayName 'cross_%s_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; Remove-Item -Path (Join-Path $D 'fw_%s.txt') -ErrorAction SilentlyContinue; `, q, q) +
		psKVDel("users.txt", user) + psKVDel("tiers.txt", user) + psKVDel("groups.txt", user) +
		fmt.Sprintf(`Remove-LocalUser -Name '%s' -ErrorAction Stop`, q)
}

func winPurgeUserCmd(user string) string { return winCmdFrom(winPurgeScript(user)) }

const winProtectedNames = `$prot = @('Administrator','DefaultAccount','Guest','WDAGUtilityAccount',$env:USERNAME); `

func winKillAllCmd() string {
	return winCmdFrom(winProtectedNames +
		`$names = @(Get-LocalUser | Where-Object { $prot -notcontains $_.Name } | ForEach-Object { $_.Name }); ` +
		`Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -and ($_.UserName -like ($env:COMPUTERNAME + '\*')) -and ($names -contains $_.UserName.Split('\')[-1]) } | Stop-Process -Force -ErrorAction SilentlyContinue`)
}

// nuke: every local account except built-ins and the account this session uses; all tool state
func winNukeCmd() string {
	return winCmdFrom(psStateInit + winProtectedNames +
		`$victims = @(Get-LocalUser | Where-Object { ($prot -notcontains $_.Name) -and ($_.SID.Value -notlike '*-500') }); ` +
		`foreach($v in $victims){ $n = $v.Name; ` +
		`Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -and ($_.UserName.Split('\')[-1] -eq $n) } | Stop-Process -Force -ErrorAction SilentlyContinue; ` +
		`Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $v.SID.Value } | Remove-CimInstance -ErrorAction SilentlyContinue; ` +
		`Remove-LocalUser -Name $n -ErrorAction SilentlyContinue }; ` +
		`$f = Join-Path $D 'ips.txt'; if(Test-Path $f){ Get-Content $f | ForEach-Object { $i = $_.IndexOf(':'); if($i -gt 0){ Get-NetIPAddress -IPAddress ($_.Substring($i+1).Split('/')[0]) -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue } } }; ` +
		`Get-ScheduledTask -TaskName 'cross_ip_*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue; ` +
		`Get-NetFirewallRule -DisplayName 'cross_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; ` +
		`Get-ChildItem -Path $D -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue`)
}

func winDryRun(client *ssh.Client) {
	fmt.Println(common.Cyan + "\n[+] Running pre-flight Mass Purge simulation for Windows..." + common.Reset)
	script := psStateRead + winProtectedNames + `
Write-Output '=== DRY RUN SAFETY AUDIT REPORT ===';
Write-Output '';
Write-Output '[OK] IMMUNE / PROTECTED IDENTITIES (Will NEVER be touched):';
Get-LocalUser | Where-Object { ($prot -contains $_.Name) -or ($_.SID.Value -like '*-500') } | ForEach-Object { Write-Output ('  * ' + $_.Name + ' -> [SAFE / PROTECTED]') };
Write-Output '';
Write-Output '[!] TARGET IDENTITIES QUEUED FOR MASS PURGE:';
$v = @(Get-LocalUser | Where-Object { ($prot -notcontains $_.Name) -and ($_.SID.Value -notlike '*-500') });
if($v.Count -eq 0){ Write-Output '  * None.' } else { $v | ForEach-Object { Write-Output ('  * ' + $_.Name + ' -> [SCHEDULED FOR DELETION]') } };
Write-Output '';
Write-Output '[!] STACKED IP CLEANUP PREVIEW:';
$f = Join-Path $D 'ips.txt'; if(Test-Path $f){ Get-Content $f | ForEach-Object { Write-Output ('  * Unbind ' + $_) } } else { Write-Output '  * No stacked IPs registered.' };
Write-Output '';
Write-Output '=== DRY RUN VERDICT: SIMULATION COMPLETED SAFELY (ZERO CHANGES APPLIED) ===';`
	out, err := psExec(client, script)
	if err == nil {
		fmt.Println(common.Green + out + common.Reset)
	}
}
