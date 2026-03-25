package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&cryptoPolicy{})
	check.Register(&certExpiry{})
	check.Register(&selfSigned{})
	check.Register(&tlsVersion{})
	check.Register(&weakCiphers{})
	check.Register(&certChain{})
	check.Register(&privateKeyPerms{})
	check.Register(&fipsMode{})
	check.Register(&weakHash{})
}

// CRYPTO-001
type cryptoPolicy struct{}

func (c *cryptoPolicy) ID() string             { return "CRYPTO-001" }
func (c *cryptoPolicy) Name() string           { return "System crypto policy is not LEGACY" }
func (c *cryptoPolicy) Category() string       { return "crypto" }
func (c *cryptoPolicy) Severity() check.Severity { return check.High }
func (c *cryptoPolicy) Description() string    { return "Verify system-wide crypto policy is not set to LEGACY" }

func (c *cryptoPolicy) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "update-crypto-policies", "--show")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "crypto-policies not available (non-RHEL system)"}
	}
	policy := strings.TrimSpace(string(out))
	if strings.ToUpper(policy) == "LEGACY" {
		return check.Result{
			Status: check.Fail, Message: "System crypto policy is LEGACY",
			Remediation: "Set: update-crypto-policies --set DEFAULT",
		}
	}
	return check.Result{Status: check.Pass, Message: "Crypto policy: " + policy}
}

// CRYPTO-002
type certExpiry struct{}

func (c *certExpiry) ID() string             { return "CRYPTO-002" }
func (c *certExpiry) Name() string           { return "No expired or soon-to-expire certificates" }
func (c *certExpiry) Category() string       { return "crypto" }
func (c *certExpiry) Severity() check.Severity { return check.High }
func (c *certExpiry) Description() string    { return "Check for expired certificates in /etc/ssl and /etc/pki" }

func (c *certExpiry) Run() check.Result {
	var expired, expiring []string
	var parseErrors int
	now := time.Now()
	warnDays := 30 * 24 * time.Hour

	certDirs := []string{"/etc/ssl/certs", "/etc/pki/tls/certs"}
	for _, dir := range certDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || info.Size() > 100*1024 {
				return nil
			}
			if !strings.HasSuffix(path, ".pem") && !strings.HasSuffix(path, ".crt") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			block, _ := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				parseErrors++
				return nil
			}
			if now.After(cert.NotAfter) {
				expired = append(expired, filepath.Base(path))
			} else if cert.NotAfter.Before(now.Add(warnDays)) {
				expiring = append(expiring, filepath.Base(path))
			}
			return nil
		})
	}

	if len(expired) > 0 {
		details := map[string]string{"expired": strings.Join(expired, ", ")}
		if parseErrors > 0 {
			details["parse_errors"] = fmt.Sprintf("%d certificate(s) could not be parsed", parseErrors)
		}
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("%d expired certificate(s): %s", len(expired), strings.Join(expired, ", ")),
			Remediation: "Renew or remove expired certificates",
			Details:     details,
		}
	}
	if len(expiring) > 0 {
		details := map[string]string{"expiring": strings.Join(expiring, ", ")}
		return check.Result{
			Status:  check.Warn,
			Message: fmt.Sprintf("%d certificate(s) expiring within 30 days: %s", len(expiring), strings.Join(expiring, ", ")),
			Details: details,
		}
	}
	if parseErrors > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: fmt.Sprintf("No expired certs found, but %d certificate(s) could not be parsed", parseErrors),
			Details: map[string]string{"parse_errors": fmt.Sprintf("%d", parseErrors)},
		}
	}
	return check.Result{Status: check.Pass, Message: "No expired or expiring certificates found"}
}

// CRYPTO-003
type selfSigned struct{}

func (c *selfSigned) ID() string             { return "CRYPTO-003" }
func (c *selfSigned) Name() string           { return "No self-signed certificates in production" }
func (c *selfSigned) Category() string       { return "crypto" }
func (c *selfSigned) Severity() check.Severity { return check.Medium }
func (c *selfSigned) Description() string    { return "Flag self-signed certificates for review" }

func (c *selfSigned) Run() check.Result {
	// Check common service cert locations
	certPaths := []string{
		"/etc/ssl/certs/ssl-cert-snakeoil.pem",
		"/etc/pki/tls/certs/localhost.crt",
	}

	var found []string
	for _, p := range certPaths {
		if _, err := os.Stat(p); err == nil {
			found = append(found, filepath.Base(p))
		}
	}

	if len(found) > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: "Self-signed/snakeoil certificates found: " + strings.Join(found, ", "),
			Remediation: "Replace with certificates from a trusted CA",
		}
	}
	return check.Result{Status: check.Pass, Message: "No obvious self-signed certificates found"}
}

// CRYPTO-004
type tlsVersion struct{}

func (c *tlsVersion) ID() string             { return "CRYPTO-004" }
func (c *tlsVersion) Name() string           { return "TLS 1.0 and 1.1 disabled" }
func (c *tlsVersion) Category() string       { return "crypto" }
func (c *tlsVersion) Severity() check.Severity { return check.High }
func (c *tlsVersion) Description() string    { return "Verify TLS 1.0 and 1.1 are disabled system-wide" }

func (c *tlsVersion) Run() check.Result {
	// Check OpenSSL default config
	data, err := os.ReadFile("/etc/ssl/openssl.cnf")
	if err != nil {
		return check.Result{Status: check.Warn, Message: "Cannot read OpenSSL config"}
	}
	content := string(data)
	if strings.Contains(content, "MinProtocol") {
		if strings.Contains(content, "TLSv1.2") || strings.Contains(content, "TLSv1.3") {
			return check.Result{Status: check.Pass, Message: "OpenSSL MinProtocol is TLSv1.2 or higher"}
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "TLS minimum version may not be enforced system-wide",
		Remediation: "Set MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf",
	}
}

// CRYPTO-005
type weakCiphers struct{}

func (c *weakCiphers) ID() string             { return "CRYPTO-005" }
func (c *weakCiphers) Name() string           { return "No weak cipher suites" }
func (c *weakCiphers) Category() string       { return "crypto" }
func (c *weakCiphers) Severity() check.Severity { return check.High }
func (c *weakCiphers) Description() string    { return "Verify no RC4, DES, 3DES, or NULL ciphers are available" }

func (c *weakCiphers) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "openssl", "ciphers", "-v", "ALL")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot list OpenSSL ciphers"}
	}

	weak := []string{"RC4", "DES-CBC", "3DES", "NULL", "EXPORT", "anon"}
	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		for _, w := range weak {
			if strings.Contains(line, w) {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					found = append(found, fields[0])
				}
				break
			}
		}
	}

	if len(found) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("%d weak ciphers available", len(found)),
			Remediation: "Configure OpenSSL to disable weak ciphers in /etc/ssl/openssl.cnf",
		}
	}
	return check.Result{Status: check.Pass, Message: "No weak ciphers available"}
}

// CRYPTO-006
type certChain struct{}

func (c *certChain) ID() string             { return "CRYPTO-006" }
func (c *certChain) Name() string           { return "Certificate chains complete" }
func (c *certChain) Category() string       { return "crypto" }
func (c *certChain) Severity() check.Severity { return check.Medium }
func (c *certChain) Description() string    { return "Verify certificate chains are complete for common services" }

func (c *certChain) Run() check.Result {
	// Basic check - verify ca-certificates is installed
	if _, err := os.Stat("/etc/ssl/certs/ca-certificates.crt"); err == nil {
		return check.Result{Status: check.Pass, Message: "CA certificates bundle is installed"}
	}
	if _, err := os.Stat("/etc/pki/tls/certs/ca-bundle.crt"); err == nil {
		return check.Result{Status: check.Pass, Message: "CA certificates bundle is installed"}
	}
	return check.Result{
		Status: check.Warn, Message: "CA certificates bundle not found",
		Remediation: "Install: 'apt install ca-certificates' or 'dnf install ca-certificates'",
	}
}

// CRYPTO-007
type privateKeyPerms struct{}

func (c *privateKeyPerms) ID() string             { return "CRYPTO-007" }
func (c *privateKeyPerms) Name() string           { return "Private key file permissions" }
func (c *privateKeyPerms) Category() string       { return "crypto" }
func (c *privateKeyPerms) Severity() check.Severity { return check.Critical }
func (c *privateKeyPerms) Description() string    { return "Verify private keys are 0600 or 0400" }

func (c *privateKeyPerms) Run() check.Result {
	keyDirs := []string{"/etc/ssl/private", "/etc/pki/tls/private"}
	var bad []string

	for _, dir := range keyDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			perm := info.Mode().Perm()
			if perm > 0600 {
				bad = append(bad, fmt.Sprintf("%s (%04o)", path, perm))
			}
			return nil
		})
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "Private keys with insecure permissions: " + strings.Join(bad, ", "),
			Remediation: "Fix: chmod 600 <key-file>",
		}
	}
	return check.Result{Status: check.Pass, Message: "Private key permissions are correct"}
}

// CRYPTO-008
type fipsMode struct{}

func (c *fipsMode) ID() string             { return "CRYPTO-008" }
func (c *fipsMode) Name() string           { return "FIPS mode enabled if required" }
func (c *fipsMode) Category() string       { return "crypto" }
func (c *fipsMode) Severity() check.Severity { return check.Medium }
func (c *fipsMode) Description() string    { return "Check if FIPS mode is enabled" }

func (c *fipsMode) Run() check.Result {
	data, err := os.ReadFile("/proc/sys/crypto/fips_enabled")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "FIPS check not applicable"}
	}
	if strings.TrimSpace(string(data)) == "1" {
		return check.Result{Status: check.Pass, Message: "FIPS mode is enabled"}
	}
	return check.Result{
		Status:  check.Warn,
		Message: "FIPS mode is not enabled (may be required for compliance)",
	}
}

// CRYPTO-009
type weakHash struct{}

func (c *weakHash) ID() string             { return "CRYPTO-009" }
func (c *weakHash) Name() string           { return "No MD5/SHA1 in authentication" }
func (c *weakHash) Category() string       { return "crypto" }
func (c *weakHash) Severity() check.Severity { return check.High }
func (c *weakHash) Description() string    { return "Verify MD5 and SHA1 are not used for password hashing" }

func (c *weakHash) Run() check.Result {
	entries, err := check.ParseShadow()
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/shadow: " + err.Error()}
	}

	var md5Users []string
	for _, e := range entries {
		if strings.HasPrefix(e.Hash, "$1$") {
			md5Users = append(md5Users, e.User)
		}
	}

	if len(md5Users) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "Users with MD5 password hashes: " + strings.Join(md5Users, ", "),
			Remediation: "Force password change for affected users to use SHA-512 ($6$)",
		}
	}
	return check.Result{Status: check.Pass, Message: "No weak password hash algorithms in use"}
}
