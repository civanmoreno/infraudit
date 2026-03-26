package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/civanmoreno/infraudit/internal/remote"
	"github.com/spf13/cobra"
)

var (
	scanHost        string
	scanHostsFile   string
	scanIdentity    string
	scanPort        int
	scanUser        string
	scanSudo        bool
	scanBinary      string
	scanConcurrency int
	scanTimeout     time.Duration
	scanFormat      string
	scanOutput      string
	scanCategory    string
	scanProfile     string
	scanSkip        string
	scanKeepBinary  bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Audit remote servers via SSH",
	Long: `Audit remote Linux servers by copying the infraudit binary over SSH,
executing the audit remotely, and collecting the results.

No installation required on the remote server — the binary is copied
to /tmp, executed, and cleaned up automatically.

Examples:
  infraudit scan --host root@192.168.1.10
  infraudit scan --host deploy@server.com:2222 --sudo
  infraudit scan --hosts servers.txt --concurrency 5
  infraudit scan --host root@server.com --format json --output report.json`,
	Run: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanHost, "host", "", "Remote host: [user@]host[:port]")
	scanCmd.Flags().StringVar(&scanHostsFile, "hosts", "", "Path to file with hosts (one per line)")
	scanCmd.Flags().StringVar(&scanIdentity, "identity", "", "SSH private key path")
	scanCmd.Flags().IntVar(&scanPort, "port", 22, "Default SSH port")
	scanCmd.Flags().StringVar(&scanUser, "user", "", "Default SSH user")
	scanCmd.Flags().BoolVar(&scanSudo, "sudo", false, "Run remote audit with sudo")
	scanCmd.Flags().StringVar(&scanBinary, "binary", "", "Path to binary to deploy (overrides auto-detection)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 5, "Max concurrent host scans")
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 5*time.Minute, "Per-host timeout")
	scanCmd.Flags().StringVar(&scanFormat, "format", "console", "Output format: console, json")
	scanCmd.Flags().StringVar(&scanOutput, "output", "", "Write report to file")
	scanCmd.Flags().StringVar(&scanCategory, "category", "", "Pass-through: audit category filter")
	scanCmd.Flags().StringVar(&scanProfile, "profile", "", "Pass-through: server profile")
	scanCmd.Flags().StringVar(&scanSkip, "skip", "", "Pass-through: checks to skip")
	scanCmd.Flags().BoolVar(&scanKeepBinary, "keep-binary", false, "Don't remove binary from remote after scan")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) {
	// Parse hosts
	hosts, err := parseScanHosts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Apply defaults
	for i := range hosts {
		if hosts[i].User == "" && scanUser != "" {
			hosts[i].User = scanUser
		}
		if hosts[i].Port == 22 && scanPort != 22 {
			hosts[i].Port = scanPort
		}
		if scanIdentity != "" {
			hosts[i].Identity = scanIdentity
		}
	}

	// Build audit pass-through args
	var auditArgs []string
	if scanCategory != "" {
		auditArgs = append(auditArgs, "--category", scanCategory)
	}
	if scanProfile != "" {
		auditArgs = append(auditArgs, "--profile", scanProfile)
	}
	if scanSkip != "" {
		auditArgs = append(auditArgs, "--skip", scanSkip)
	}

	// Create scanner
	scanner := &remote.Scanner{
		BinaryPath: scanBinary,
		Timeout:    scanTimeout,
		AuditArgs:  auditArgs,
		UseSudo:    scanSudo,
		KeepBinary: scanKeepBinary,
	}

	// Progress output
	fmt.Fprintf(os.Stderr, "\n  Scanning %d host(s)...\n\n", len(hosts))

	// Execute scans
	results := scanner.ScanHosts(hosts, scanConcurrency)

	// Print progress per host
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "  %s✗%s %s: %s\n", red, rst, r.Host, r.Err)
		} else {
			fmt.Fprintf(os.Stderr, "  %s✓%s %s: score %d/100 (%s)\n",
				green, rst, r.Host, r.Report.Summary.Score, r.Report.Summary.Grade)
		}
	}
	fmt.Fprintln(os.Stderr)

	// Determine output writer
	w := os.Stdout
	var outFile *os.File
	if scanOutput != "" {
		f, err := os.Create(scanOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		outFile = f
		w = f
	}

	// Write output
	var writeErr error
	switch scanFormat {
	case "json":
		writeErr = remote.WriteJSON(w, results)
	default:
		if len(results) == 1 {
			remote.WriteSingleConsole(w, results[0])
		} else {
			remote.WriteConsole(w, results)
		}
	}

	if outFile != nil {
		outFile.Close()
	}

	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", writeErr)
		os.Exit(1)
	}

	// Exit code: worst result across all hosts
	os.Exit(scanExitCode(results))
}

func parseScanHosts() ([]remote.Host, error) {
	if scanHost == "" && scanHostsFile == "" {
		return nil, fmt.Errorf("specify --host or --hosts")
	}
	if scanHost != "" && scanHostsFile != "" {
		return nil, fmt.Errorf("--host and --hosts are mutually exclusive")
	}

	if scanHost != "" {
		h, err := remote.ParseHost(scanHost)
		if err != nil {
			return nil, err
		}
		return []remote.Host{h}, nil
	}

	return remote.ParseHostsFile(scanHostsFile)
}

func scanExitCode(results []remote.ScanResult) int {
	worst := 0
	hasOperationalErr := false

	for _, r := range results {
		if r.Err != nil {
			hasOperationalErr = true
			continue
		}
		if r.Report == nil {
			continue
		}
		s := r.Report.Summary
		switch {
		case s.Failures > 0 || s.Errors > 0:
			if worst < 2 {
				worst = 2
			}
		case s.Warnings > 0:
			if worst < 1 {
				worst = 1
			}
		}
	}

	// Operational errors are exit code 3
	if hasOperationalErr && worst < 3 {
		worst = 3
	}
	return worst
}
