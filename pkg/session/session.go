package session

import (
	"fmt"
	"net"
	"time"

	"cross-ssh/pkg/osdetect"
	"golang.org/x/crypto/ssh"
)

type ActiveSession struct {
	Host     string
	Port     string
	User     string
	Pass     string
	KeyPath  string
	TargetOS osdetect.TargetOS
	Client   *ssh.Client
}

// Dial establishes an SSH connection to the remote target
func Dial(host, port, user, pass, keyPath string) (*ActiveSession, error) {
	var authMethods []ssh.AuthMethod

	if pass != "" {
		authMethods = append(authMethods, ssh.Password(pass))
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", addr, err)
	}

	targetOS, _, _ := osdetect.DetectOS(client)

	return &ActiveSession{
		Host:     host,
		Port:     port,
		User:     user,
		Pass:     pass,
		KeyPath:  keyPath,
		TargetOS: targetOS,
		Client:   client,
	}, nil
}