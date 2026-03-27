package network

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// setupFSRoot creates a temp directory and sets check.FSRoot to it.
func setupFSRoot(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	check.FSRoot = tmp
	t.Cleanup(func() {
		check.FSRoot = ""
		check.ResetCache()
	})
	return tmp
}

// writeFile creates a file under the FSRoot-prefixed path with the given content.
func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

// --- IP Forwarding (NET-003) ---

func TestIPForwarding_Disabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/ip_forward", "0\n")
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/forwarding", "0\n")

	c := &ipForwarding{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestIPForwarding_IPv4Enabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/ip_forward", "1\n")
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/forwarding", "0\n")

	c := &ipForwarding{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestIPForwarding_BothEnabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/ip_forward", "1\n")
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/forwarding", "1\n")

	c := &ipForwarding{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Source Route (NET-029) ---

func TestSourceRoute_Disabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/conf/all/accept_source_route", "0\n")

	c := &sysctlParam{
		id: "NET-029", name: "Source routed packets not accepted (all)",
		path: "/proc/sys/net/ipv4/conf/all/accept_source_route", expected: "0",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSourceRoute_Enabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/conf/all/accept_source_route", "1\n")

	c := &sysctlParam{
		id: "NET-029", name: "Source routed packets not accepted (all)",
		path: "/proc/sys/net/ipv4/conf/all/accept_source_route", expected: "0",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Redirects (NET-014, NET-012) ---

func TestRedirects_AcceptDisabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/conf/all/accept_redirects", "0\n")

	c := &sysctlParam{
		id: "NET-014", name: "ICMP redirects not accepted (all)",
		path: "/proc/sys/net/ipv4/conf/all/accept_redirects", expected: "0",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRedirects_AcceptEnabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/conf/all/accept_redirects", "1\n")

	c := &sysctlParam{
		id: "NET-014", name: "ICMP redirects not accepted (all)",
		path: "/proc/sys/net/ipv4/conf/all/accept_redirects", expected: "0",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestRedirects_SendDisabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/conf/all/send_redirects", "0\n")

	c := &sysctlParam{
		id: "NET-012", name: "Packet redirect sending disabled (all)",
		path: "/proc/sys/net/ipv4/conf/all/send_redirects", expected: "0",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRedirects_SendEnabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/conf/all/send_redirects", "1\n")

	c := &sysctlParam{
		id: "NET-012", name: "Packet redirect sending disabled (all)",
		path: "/proc/sys/net/ipv4/conf/all/send_redirects", expected: "0",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- SYN Cookies (NET-024) ---

func TestSynCookies_Enabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/tcp_syncookies", "1\n")

	c := &sysctlParam{
		id: "NET-024", name: "TCP SYN cookies enabled",
		path: "/proc/sys/net/ipv4/tcp_syncookies", expected: "1",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSynCookies_Disabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv4/tcp_syncookies", "0\n")

	c := &sysctlParam{
		id: "NET-024", name: "TCP SYN cookies enabled",
		path: "/proc/sys/net/ipv4/tcp_syncookies", expected: "1",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Sysctl Missing File ---

func TestSysctl_MissingFile(t *testing.T) {
	_ = setupFSRoot(t)

	c := &sysctlParam{
		id: "NET-024", name: "TCP SYN cookies enabled",
		path: "/proc/sys/net/ipv4/tcp_syncookies", expected: "1",
	}
	r := c.Run()
	if r.Status != check.Error {
		t.Errorf("expected ERROR, got %s: %s", r.Status, r.Message)
	}
}
