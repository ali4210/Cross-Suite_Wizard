package osdetect

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

type TargetOS string

const (
	OSLinux   TargetOS = "linux"
	OSMacOS   TargetOS = "darwin"
	OSWindows TargetOS = "windows"
)

func DetectOS(client *ssh.Client) (TargetOS, bool, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", false, err
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out

	_ = session.Run("uname -s")
	stdout := strings.TrimSpace(out.String())

	if strings.Contains(strings.ToLower(stdout), "linux") {
		return OSLinux, false, nil
	}
	if strings.Contains(strings.ToLower(stdout), "darwin") {
		return OSMacOS, false, nil
	}

	winSession, err := client.NewSession()
	if err == nil {
		defer winSession.Close()
		var winOut bytes.Buffer
		winSession.Stdout = &winOut
		if err := winSession.Run("cmd /c echo %OS%"); err == nil {
			if strings.Contains(strings.ToLower(winOut.String()), "windows_nt") {
				isAdmin := checkWindowsAdmin(client)
				return OSWindows, isAdmin, nil
			}
		}
	}

	return "", false, fmt.Errorf("could not determine target OS: uname output=%q, windows probe failed", stdout)
}

func checkWindowsAdmin(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	_ = session.Run("net session")
	return !strings.Contains(out.String(), "Access is denied")
}
