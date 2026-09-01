package telnet

import (
	"bufio"
	"net"
	"time"
)

type ProbeResult struct {
	Host        string
	Port        string
	IsOpen      bool
	Banner      string
	LatencyMs   int64
	ErrorReason string
}

// ProbePort checks TCP connectivity with clean deadline handling
func ProbePort(host string, port string, timeoutSeconds int) ProbeResult {
	address := net.JoinHostPort(host, port)
	start := time.Now()

	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return ProbeResult{
			Host:        host,
			Port:        port,
			IsOpen:      false,
			LatencyMs:   latency,
			ErrorReason: err.Error(),
		}
	}
	defer conn.Close()

	// Try non-blocking short banner read
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil && banner == "" {
		banner = "TCP Port Active (No Banner Broadcasted)"
	}

	return ProbeResult{
		Host:      host,
		Port:      port,
		IsOpen:    true,
		Banner:    banner,
		LatencyMs: latency,
	}
}