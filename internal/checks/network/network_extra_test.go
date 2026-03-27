package network

import (
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// =============================================================
// SNMP Community (NET-010) — snmp_community.go
// =============================================================

func TestSNMPCommunity_NoSNMP(t *testing.T) {
	_ = setupFSRoot(t) // no snmpd.conf created
	c := &snmpCommunity{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no SNMP), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPCommunity_DefaultPublic(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"# SNMP config\nrocommunity public\nrocommunity6 public\n")

	c := &snmpCommunity{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL (default public), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPCommunity_DefaultPrivate(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"rwcommunity private\n")

	c := &snmpCommunity{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL (default private), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPCommunity_CustomString_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"rocommunity s3cretStr1ng\n")

	c := &snmpCommunity{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (custom community), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPCommunity_CommentsIgnored(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"# rocommunity public\n# rwcommunity private\nrocommunity myCustom\n")

	c := &snmpCommunity{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (comments ignored), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// SNMP Version (NET-009) — snmp_version.go
// =============================================================

func TestSNMPVersion_NoSNMP(t *testing.T) {
	_ = setupFSRoot(t)
	c := &snmpVersion{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no SNMP), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPVersion_V1V2cPresent(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"rocommunity mySecret\n")

	c := &snmpVersion{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL (v1/v2c community found), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPVersion_V3Only_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"# SNMPv3 config\ncreateUser myUser SHA authPass AES privPass\nrouser myUser\n")

	c := &snmpVersion{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (v3 only), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPVersion_CommentsIgnored(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf",
		"# rocommunity public\nrouser myUser\n")

	c := &snmpVersion{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (commented community), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// SNMP Unused (NET-011) — snmp_unused.go
// =============================================================

func TestSNMPUnused_NotInstalled(t *testing.T) {
	_ = setupFSRoot(t)
	c := &snmpUnused{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (not installed), got %s: %s", r.Status, r.Message)
	}
}

func TestSNMPUnused_InstalledNotRunning(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/snmp/snmpd.conf", "# present\n")

	c := &snmpUnused{}
	r := c.Run()
	// systemctl will fail in test env, so result should be Pass (installed but not running)
	if r.Status != check.Pass {
		t.Errorf("expected PASS (installed but not running), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// DNS Resolvers (NET-005) — dns_resolvers.go
// =============================================================

func TestDNSResolvers_NoFile(t *testing.T) {
	_ = setupFSRoot(t)
	c := &dnsResolvers{}
	r := c.Run()
	if r.Status != check.Error {
		t.Errorf("expected ERROR (no resolv.conf), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSResolvers_HasNameservers_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/resolv.conf",
		"# Generated\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")

	c := &dnsResolvers{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDNSResolvers_Empty_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/resolv.conf",
		"# No nameservers\nsearch example.com\n")

	c := &dnsResolvers{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL (no nameservers), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSResolvers_CommentsOnly_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/resolv.conf",
		"# nameserver 1.1.1.1\n# nameserver 8.8.8.8\n")

	c := &dnsResolvers{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL (only comments), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSResolvers_SingleNameserver_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/resolv.conf", "nameserver 9.9.9.9\n")

	c := &dnsResolvers{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// IPv6 Config (NET-008) — ipv6.go
// =============================================================

func TestIPv6_Disabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/disable_ipv6", "1\n")

	c := &ipv6Config{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (disabled), got %s: %s", r.Status, r.Message)
	}
}

func TestIPv6_NoInet6File(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n")
	// No /proc/net/if_inet6

	c := &ipv6Config{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no IPv6 available), got %s: %s", r.Status, r.Message)
	}
}

func TestIPv6_LoopbackOnly(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n")
	writeFile(t, root, "proc/net/if_inet6",
		"00000000000000000000000000000001 01 80 10 80       lo\n")

	c := &ipv6Config{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (loopback only), got %s: %s", r.Status, r.Message)
	}
}

func TestIPv6_MultipleInterfaces_RADisabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n")
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/accept_ra", "0\n")
	writeFile(t, root, "proc/net/if_inet6",
		"00000000000000000000000000000001 01 80 10 80       lo\n"+
			"fe80000000000000021e67fffe5e0a12 02 40 20 80    eth0\n")

	c := &ipv6Config{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (RA disabled), got %s: %s", r.Status, r.Message)
	}
}

func TestIPv6_MultipleInterfaces_RAEnabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n")
	writeFile(t, root, "proc/sys/net/ipv6/conf/all/accept_ra", "1\n")
	writeFile(t, root, "proc/net/if_inet6",
		"00000000000000000000000000000001 01 80 10 80       lo\n"+
			"fe80000000000000021e67fffe5e0a12 02 40 20 80    eth0\n")

	c := &ipv6Config{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (RA enabled), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// DNSSEC (NET-006) — dnssec.go
// =============================================================

func TestDNSSEC_EnabledInResolved(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/resolved.conf",
		"[Resolve]\nDNSSEC=yes\n")

	c := &dnssec{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (DNSSEC=yes), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSSEC_AllowDowngrade(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/resolved.conf",
		"[Resolve]\nDNSSEC=allow-downgrade\n")

	c := &dnssec{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (allow-downgrade), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSSEC_Disabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/resolved.conf",
		"[Resolve]\nDNSSEC=no\n")

	c := &dnssec{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (DNSSEC=no), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSSEC_UnboundPresent(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/unbound/unbound.conf", "server:\n")

	c := &dnssec{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (unbound), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSSEC_NothingConfigured(t *testing.T) {
	_ = setupFSRoot(t)

	c := &dnssec{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (nothing configured), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSSEC_DropInOverrides(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/resolved.conf",
		"[Resolve]\nDNSSEC=no\n")
	writeFile(t, root, "etc/systemd/resolved.conf.d/override.conf",
		"[Resolve]\nDNSSEC=yes\n")

	c := &dnssec{}
	r := c.Run()
	// The first match wins in resolvedConfValue, so no override
	// In this implementation, the base file is checked first and "no" is returned
	if r.Status != check.Warn {
		t.Errorf("expected WARN (base DNSSEC=no wins), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// DNS over TLS (NET-007) — dns_tls.go
// =============================================================

func TestDNSTLS_Enabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/resolved.conf",
		"[Resolve]\nDNSOverTLS=yes\n")

	c := &dnsTLS{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDNSTLS_Opportunistic(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/resolved.conf",
		"[Resolve]\nDNSOverTLS=opportunistic\n")

	c := &dnsTLS{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (opportunistic), got %s: %s", r.Status, r.Message)
	}
}

func TestDNSTLS_NotConfigured(t *testing.T) {
	_ = setupFSRoot(t)

	c := &dnsTLS{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// Bind Address (NET-004) — bind_address.go
// =============================================================

func TestBindAddress_NoWildcard(t *testing.T) {
	root := setupFSRoot(t)
	// Listening on 127.0.0.1 (0100007F) port 22 (0016)
	writeFile(t, root, "proc/net/tcp",
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n")

	c := &bindAddress{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestBindAddress_WildcardFound(t *testing.T) {
	root := setupFSRoot(t)
	// Listening on 0.0.0.0 (00000000) port 80 (0050)
	writeFile(t, root, "proc/net/tcp",
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n")

	c := &bindAddress{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (wildcard), got %s: %s", r.Status, r.Message)
	}
}

func TestBindAddress_NoProcFile(t *testing.T) {
	_ = setupFSRoot(t)

	c := &bindAddress{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no proc file), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// Open Ports (NET-002) — open_ports.go
// =============================================================

func TestOpenPorts_NoFile(t *testing.T) {
	_ = setupFSRoot(t)

	c := &openPorts{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no proc files), got %s: %s", r.Status, r.Message)
	}
}

func TestOpenPorts_ListeningPort(t *testing.T) {
	root := setupFSRoot(t)
	// Port 8080 (1F90) listening on 0.0.0.0
	writeFile(t, root, "proc/net/tcp",
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n")

	c := &openPorts{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (unexpected port), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// parseProcNet + hexToPort helpers
// =============================================================

func TestParseProcNet_MultipleListeners(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/net/tcp",
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111\n"+
			"   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222\n"+
			"   2: 0100007F:0050 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 333\n")

	ports := parseProcNet("/proc/net/tcp")
	if len(ports) != 2 {
		t.Errorf("expected 2 listening ports, got %d: %v", len(ports), ports)
	}
}

func TestHexToPort(t *testing.T) {
	tests := []struct {
		hex  string
		want int
	}{
		{"0016", 22},
		{"0050", 80},
		{"01BB", 443},
		{"1F90", 8080},
		{"0000", 0},
	}
	for _, tt := range tests {
		got := hexToPort(tt.hex)
		if got != tt.want {
			t.Errorf("hexToPort(%q) = %d, want %d", tt.hex, got, tt.want)
		}
	}
}
