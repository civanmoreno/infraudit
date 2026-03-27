package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/civanmoreno/infraudit/internal/check"
)

// setupFSRoot creates a temp directory, sets check.FSRoot to it,
// resets all caches, and returns the temp root path.
func setupFSRoot(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	check.FSRoot = tmp
	check.ResetCache()
	t.Cleanup(func() {
		check.FSRoot = ""
		check.ResetCache()
	})
	return tmp
}

// writeFile creates a file under the temp root at the given absolute path.
func writeFile(t *testing.T, root, absPath, content string) {
	t.Helper()
	full := filepath.Join(root, absPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

// writeFileMode creates a file with specific permissions.
func writeFileMode(t *testing.T, root, absPath, content string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, absPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// generateSelfSignedCertPEM creates a self-signed PEM certificate.
// notBefore/notAfter control the validity window.
func generateSelfSignedCertPEM(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

// --- CRYPTO-001: cryptoPolicy ---

func TestCryptoPolicy_SupportedOS(t *testing.T) {
	c := &cryptoPolicy{}
	os := c.SupportedOS()
	if len(os) != 1 || os[0] != "redhat" {
		t.Fatalf("expected SupportedOS=[redhat], got %v", os)
	}
}

// --- CRYPTO-002: certExpiry ---

func TestCertExpiry_ValidCert_Pass(t *testing.T) {
	root := setupFSRoot(t)
	certPEM := generateSelfSignedCertPEM(t,
		time.Now().Add(-24*time.Hour),
		time.Now().Add(365*24*time.Hour),
	)
	full := filepath.Join(root, "/etc/ssl/certs/valid.pem")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, certPEM, 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &certExpiry{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestCertExpiry_ExpiredCert_Fail(t *testing.T) {
	root := setupFSRoot(t)
	certPEM := generateSelfSignedCertPEM(t,
		time.Now().Add(-365*24*time.Hour),
		time.Now().Add(-1*time.Hour),
	)
	full := filepath.Join(root, "/etc/ssl/certs/expired.pem")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, certPEM, 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &certExpiry{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestCertExpiry_ExpiringSoon_Warn(t *testing.T) {
	root := setupFSRoot(t)
	certPEM := generateSelfSignedCertPEM(t,
		time.Now().Add(-24*time.Hour),
		time.Now().Add(10*24*time.Hour), // expires in 10 days (< 30 day threshold)
	)
	full := filepath.Join(root, "/etc/ssl/certs/expiring.crt")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, certPEM, 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &certExpiry{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- CRYPTO-003: selfSigned ---

func TestSelfSigned_SnakeoilPresent_Warn(t *testing.T) {
	root := setupFSRoot(t)
	certPEM := generateSelfSignedCertPEM(t,
		time.Now().Add(-24*time.Hour),
		time.Now().Add(365*24*time.Hour),
	)
	full := filepath.Join(root, "/etc/ssl/certs/ssl-cert-snakeoil.pem")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, certPEM, 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &selfSigned{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSelfSigned_NoSnakeoil_Pass(t *testing.T) {
	_ = setupFSRoot(t)

	c := &selfSigned{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- CRYPTO-004: tlsVersion ---

func TestTLSVersion_TLS12_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/ssl/openssl.cnf", "[system_default_sect]\nMinProtocol = TLSv1.2\n")

	c := &tlsVersion{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestTLSVersion_TLS13_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/ssl/openssl.cnf", "[system_default_sect]\nMinProtocol = TLSv1.3\n")

	c := &tlsVersion{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestTLSVersion_TLS1_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/ssl/openssl.cnf", "[system_default_sect]\nMinProtocol = TLSv1\n")

	c := &tlsVersion{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestTLSVersion_NoConfig_Warn(t *testing.T) {
	_ = setupFSRoot(t)

	c := &tlsVersion{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- CRYPTO-007: privateKeyPerms ---

func TestPrivateKeyPerms_0600_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFileMode(t, root, "/etc/ssl/private/server.key", "PRIVATE KEY DATA", 0o600)

	c := &privateKeyPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPrivateKeyPerms_0400_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFileMode(t, root, "/etc/ssl/private/server.key", "PRIVATE KEY DATA", 0o400)

	c := &privateKeyPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPrivateKeyPerms_0644_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFileMode(t, root, "/etc/ssl/private/server.key", "PRIVATE KEY DATA", 0o644)

	c := &privateKeyPerms{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- CRYPTO-008: fipsMode ---

func TestFIPSMode_Enabled_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/crypto/fips_enabled", "1")

	c := &fipsMode{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFIPSMode_Disabled_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/crypto/fips_enabled", "0")

	c := &fipsMode{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestFIPSMode_NoFile_Pass(t *testing.T) {
	_ = setupFSRoot(t)

	c := &fipsMode{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS (not applicable), got %s: %s", r.Status, r.Message)
	}
}

// --- CRYPTO-009: weakHash ---

func TestWeakHash_SHA512_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/shadow",
		"root:$6$rounds=5000$saltsalt$hashhashhash:19000:0:99999:7:::\n"+
			"user:$6$saltsalt$anotherhash:19000:0:99999:7:::\n")

	c := &weakHash{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestWeakHash_MD5_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/shadow",
		"root:$6$saltsalt$hashhashhash:19000:0:99999:7:::\n"+
			"baduser:$1$saltsalt$md5hash:19000:0:99999:7:::\n")

	c := &weakHash{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}
