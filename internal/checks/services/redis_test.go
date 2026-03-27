package services

import (
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

func TestRedisAuth_NotInstalled(t *testing.T) {
	tmp := setupFSRoot(t)
	_ = tmp // no redis config created

	c := &redisAuth{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS when Redis not installed, got %s: %s", r.Status, r.Message)
	}
}

func TestRedisAuth_RequirepassSet(t *testing.T) {
	tmp := setupFSRoot(t)
	writeFile(t, tmp, "etc/redis/redis.conf", `# Redis config
bind 127.0.0.1
port 6379
requirepass s3cur3P@ssw0rd!
`)

	c := &redisAuth{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS with requirepass set, got %s: %s", r.Status, r.Message)
	}
}

func TestRedisAuth_NoRequirepass(t *testing.T) {
	tmp := setupFSRoot(t)
	writeFile(t, tmp, "etc/redis/redis.conf", `# Redis config
bind 127.0.0.1
port 6379
# requirepass is commented out
`)

	c := &redisAuth{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL without requirepass, got %s: %s", r.Status, r.Message)
	}
	if r.Remediation == "" {
		t.Error("expected remediation message")
	}
}

func TestRedisAuth_EmptyRequirepass(t *testing.T) {
	tmp := setupFSRoot(t)
	writeFile(t, tmp, "etc/redis/redis.conf", `bind 127.0.0.1
requirepass ""
`)

	c := &redisAuth{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL with empty requirepass, got %s: %s", r.Status, r.Message)
	}
}

func TestRedisAuth_AlternateConfigPath(t *testing.T) {
	tmp := setupFSRoot(t)
	writeFile(t, tmp, "etc/redis.conf", `requirepass mypassword
`)

	c := &redisAuth{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS with /etc/redis.conf, got %s: %s", r.Status, r.Message)
	}
}

func TestRedisAuth_Metadata(t *testing.T) {
	c := &redisAuth{}
	if c.ID() != "SVC-057" {
		t.Errorf("ID = %q, want SVC-057", c.ID())
	}
	if c.Category() != "services" {
		t.Errorf("Category = %q, want services", c.Category())
	}
	if c.Severity() != check.High {
		t.Errorf("Severity = %v, want HIGH", c.Severity())
	}
}
