package checks_test

import (
	"regexp"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"

	// Register all checks
	_ "github.com/civanmoreno/infraudit/internal/checks/auth"
	_ "github.com/civanmoreno/infraudit/internal/checks/backup"
	_ "github.com/civanmoreno/infraudit/internal/checks/boot"
	_ "github.com/civanmoreno/infraudit/internal/checks/container"
	_ "github.com/civanmoreno/infraudit/internal/checks/cron"
	_ "github.com/civanmoreno/infraudit/internal/checks/crypto"
	_ "github.com/civanmoreno/infraudit/internal/checks/filesystem"
	_ "github.com/civanmoreno/infraudit/internal/checks/hardening"
	_ "github.com/civanmoreno/infraudit/internal/checks/logging"
	_ "github.com/civanmoreno/infraudit/internal/checks/malware"
	_ "github.com/civanmoreno/infraudit/internal/checks/network"
	_ "github.com/civanmoreno/infraudit/internal/checks/nfs"
	_ "github.com/civanmoreno/infraudit/internal/checks/packages"
	_ "github.com/civanmoreno/infraudit/internal/checks/pam"
	_ "github.com/civanmoreno/infraudit/internal/checks/rlimit"
	_ "github.com/civanmoreno/infraudit/internal/checks/secrets"
	_ "github.com/civanmoreno/infraudit/internal/checks/services"
)

var validCategories = map[string]bool{
	"auth": true, "pam": true, "network": true, "services": true,
	"filesystem": true, "logging": true, "packages": true, "hardening": true,
	"boot": true, "cron": true, "crypto": true, "secrets": true,
	"container": true, "rlimit": true, "nfs": true, "malware": true,
	"backup": true,
}

var idPattern = regexp.MustCompile(`^[A-Z]+-\d{3}$`)

func TestAllChecksRegistered(t *testing.T) {
	all := check.All()
	if len(all) < 100 {
		t.Fatalf("expected at least 100 checks, got %d", len(all))
	}
	t.Logf("Total checks registered: %d", len(all))
}

func TestNoDuplicateIDs(t *testing.T) {
	all := check.All()
	seen := make(map[string]bool, len(all))
	for _, c := range all {
		id := c.ID()
		if seen[id] {
			t.Errorf("duplicate check ID: %s", id)
		}
		seen[id] = true
	}
}

func TestIDFormat(t *testing.T) {
	for _, c := range check.All() {
		if !idPattern.MatchString(c.ID()) {
			t.Errorf("check ID %q does not match pattern PREFIX-NNN", c.ID())
		}
	}
}

func TestValidCategories(t *testing.T) {
	for _, c := range check.All() {
		if !validCategories[c.Category()] {
			t.Errorf("check %s has unknown category %q", c.ID(), c.Category())
		}
	}
}

func TestValidSeverities(t *testing.T) {
	for _, c := range check.All() {
		sev := c.Severity()
		if sev < check.Info || sev > check.Critical {
			t.Errorf("check %s has invalid severity %d", c.ID(), sev)
		}
	}
}

func TestNonEmptyFields(t *testing.T) {
	for _, c := range check.All() {
		if c.ID() == "" {
			t.Error("check has empty ID")
		}
		if c.Name() == "" {
			t.Errorf("check %s has empty Name", c.ID())
		}
		if c.Description() == "" {
			t.Errorf("check %s has empty Description", c.ID())
		}
	}
}

func TestCategoryCoverage(t *testing.T) {
	found := make(map[string]bool)
	for _, c := range check.All() {
		found[c.Category()] = true
	}
	for cat := range validCategories {
		if !found[cat] {
			t.Errorf("category %q has no registered checks", cat)
		}
	}
}

func TestIDPrefixMatchesCategory(t *testing.T) {
	prefixes := map[string]string{
		"auth": "AUTH", "pam": "PAM", "network": "NET", "services": "SVC",
		"filesystem": "FS", "logging": "LOG", "packages": "PKG",
		"hardening": "HARD", "boot": "BOOT", "cron": "CRON",
		"crypto": "CRYPTO", "secrets": "SEC", "container": "CTR",
		"rlimit": "RLIM", "nfs": "NFS", "malware": "MAL", "backup": "BAK",
	}
	for _, c := range check.All() {
		expected := prefixes[c.Category()]
		id := c.ID()
		// Extract prefix (everything before the dash)
		dash := 0
		for i, ch := range id {
			if ch == '-' {
				dash = i
				break
			}
		}
		got := id[:dash]
		if got != expected {
			t.Errorf("check %s in category %q has prefix %q, expected %q", id, c.Category(), got, expected)
		}
	}
}
