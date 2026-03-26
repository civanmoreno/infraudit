package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/civanmoreno/infraudit/internal/report"
)

// ScanResult holds the outcome of scanning a single host.
type ScanResult struct {
	Host   string
	Report *report.Report
	Err    error
}

// Scanner handles remote audit execution via SSH.
type Scanner struct {
	BinaryPath string
	Timeout    time.Duration
	AuditArgs  []string
	UseSudo    bool
	KeepBinary bool
}

// ScanHost audits a single remote host.
func (s *Scanner) ScanHost(host Host) ScanResult {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	result := ScanResult{Host: host.String()}

	// Step 1: Detect remote architecture
	arch, err := s.detectArch(ctx, host)
	if err != nil {
		result.Err = fmt.Errorf("detect arch: %w", err)
		return result
	}

	// Step 2: Resolve local binary for remote arch
	binaryPath, err := s.resolveBinary(arch)
	if err != nil {
		result.Err = fmt.Errorf("resolve binary: %w", err)
		return result
	}

	// Step 3: Generate remote path
	remotePath := remoteTmpPath()

	// Step 4: Upload binary
	if err := s.upload(ctx, host, binaryPath, remotePath); err != nil {
		result.Err = fmt.Errorf("upload: %w", err)
		return result
	}

	// Step 5: Make executable
	if err := s.remoteExec(ctx, host, "chmod", "700", remotePath); err != nil {
		s.cleanup(ctx, host, remotePath)
		result.Err = fmt.Errorf("chmod: %w", err)
		return result
	}

	// Step 6: Execute audit
	jsonOut, err := s.executeAudit(ctx, host, remotePath)

	// Step 7: Cleanup (always, unless --keep-binary)
	if !s.KeepBinary {
		s.cleanup(ctx, host, remotePath)
	}

	if err != nil {
		result.Err = fmt.Errorf("execute: %w", err)
		return result
	}

	// Step 8: Parse JSON output
	var r report.Report
	if err := json.Unmarshal(jsonOut, &r); err != nil {
		result.Err = fmt.Errorf("parse output: %w (raw: %s)", err, truncate(string(jsonOut), 200))
		return result
	}
	result.Report = &r
	return result
}

// ScanHosts audits multiple hosts concurrently.
func (s *Scanner) ScanHosts(hosts []Host, concurrency int) []ScanResult {
	if concurrency < 1 {
		concurrency = 1
	}

	results := make([]ScanResult, len(hosts))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, host Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = s.ScanHost(host)
		}(i, h)
	}
	wg.Wait()
	return results
}

func (s *Scanner) detectArch(ctx context.Context, host Host) (string, error) {
	args := sshArgs(host, "uname", "-m")
	out, err := runSSH(ctx, args)
	if err != nil {
		return "", err
	}
	return mapArch(strings.TrimSpace(string(out)))
}

func (s *Scanner) resolveBinary(remoteArch string) (string, error) {
	// Explicit binary path takes priority
	if s.BinaryPath != "" {
		if _, err := os.Stat(s.BinaryPath); err != nil {
			return "", fmt.Errorf("binary not found: %s", s.BinaryPath)
		}
		return s.BinaryPath, nil
	}

	localArch := runtime.GOARCH

	// Same architecture: use current executable
	if localArch == remoteArch {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("get executable path: %w", err)
		}
		return exe, nil
	}

	// Different architecture: look for cross-compiled binary
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	candidates := []string{
		filepath.Join(exeDir, fmt.Sprintf("infraudit-linux-%s", remoteArch)),
		filepath.Join("dist", fmt.Sprintf("infraudit-linux-%s", remoteArch)),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf(
		"remote host is %s but no matching binary found; "+
			"use --binary or run 'make release' to cross-compile",
		remoteArch,
	)
}

func (s *Scanner) upload(ctx context.Context, host Host, localPath, remotePath string) error {
	args := scpArgs(host, localPath, remotePath)
	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

func (s *Scanner) executeAudit(ctx context.Context, host Host, remotePath string) ([]byte, error) {
	cmdParts := []string{}
	if s.UseSudo {
		cmdParts = append(cmdParts, "sudo")
	}
	cmdParts = append(cmdParts, remotePath, "audit", "--format", "json")
	cmdParts = append(cmdParts, s.AuditArgs...)

	args := sshArgs(host, cmdParts...)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Exit codes 1 (warnings) and 2 (failures) are normal audit results
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if code == 1 || code == 2 {
				return stdout.Bytes(), nil
			}
		}
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (s *Scanner) remoteExec(ctx context.Context, host Host, cmdParts ...string) error {
	args := sshArgs(host, cmdParts...)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

func (s *Scanner) cleanup(ctx context.Context, host Host, remotePath string) {
	// Best effort, ignore errors
	cleanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = s.remoteExec(cleanCtx, host, "rm", "-f", remotePath)
}

// sshArgs builds the argument list for an ssh command.
func sshArgs(host Host, extra ...string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
	}
	if host.Port != 0 && host.Port != 22 {
		args = append(args, "-p", strconv.Itoa(host.Port))
	}
	if host.Identity != "" {
		args = append(args, "-i", host.Identity)
	}
	target := host.Address
	if host.User != "" {
		target = host.User + "@" + host.Address
	}
	args = append(args, target)
	args = append(args, extra...)
	return args
}

// scpArgs builds the argument list for an scp command.
func scpArgs(host Host, localPath, remotePath string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
	}
	if host.Port != 0 && host.Port != 22 {
		args = append(args, "-P", strconv.Itoa(host.Port))
	}
	if host.Identity != "" {
		args = append(args, "-i", host.Identity)
	}
	target := host.Address
	if host.User != "" {
		target = host.User + "@" + host.Address
	}
	args = append(args, localPath, target+":"+remotePath)
	return args
}

// mapArch maps uname -m output to Go architecture names.
func mapArch(uname string) (string, error) {
	switch uname {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", uname)
	}
}

func remoteTmpPath() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "/tmp/infraudit-scan-" + hex.EncodeToString(b)
}

func runSSH(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
