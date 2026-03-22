package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShouldSkipByID(t *testing.T) {
	cfg := &Config{Skip: []string{"AUTH-001", "NET-002"}}
	if !cfg.ShouldSkip("AUTH-001", "auth") {
		t.Fatal("expected AUTH-001 to be skipped")
	}
	if cfg.ShouldSkip("AUTH-002", "auth") {
		t.Fatal("expected AUTH-002 not to be skipped")
	}
}

func TestShouldSkipByCategory(t *testing.T) {
	cfg := &Config{SkipCategories: []string{"container", "nfs"}}
	if !cfg.ShouldSkip("CTR-001", "container") {
		t.Fatal("expected container category to be skipped")
	}
	if cfg.ShouldSkip("NET-001", "network") {
		t.Fatal("expected network category not to be skipped")
	}
}

func TestShouldSkipEmpty(t *testing.T) {
	cfg := &Config{}
	if cfg.ShouldSkip("AUTH-001", "auth") {
		t.Fatal("expected nothing to be skipped with empty config")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	err := os.WriteFile(cfgPath, []byte(`{"skip":["AUTH-001"],"allowed_ports":[22,80]}`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := loadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Skip) != 1 || cfg.Skip[0] != "AUTH-001" {
		t.Fatalf("unexpected skip: %v", cfg.Skip)
	}
	if len(cfg.AllowedPorts) != 2 {
		t.Fatalf("unexpected ports: %v", cfg.AllowedPorts)
	}
}

func TestLoadFileMissing(t *testing.T) {
	_, err := loadFile("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	os.WriteFile(cfgPath, []byte(`{invalid`), 0600)

	_, err := loadFile(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGetSetGlobal(t *testing.T) {
	original := globalCfg
	defer func() { globalCfg = original }()

	cfg := &Config{Skip: []string{"TEST-001"}}
	Set(cfg)
	got := Get()
	if len(got.Skip) != 1 || got.Skip[0] != "TEST-001" {
		t.Fatalf("unexpected config: %v", got)
	}
}

func TestGetNilReturnsEmpty(t *testing.T) {
	original := globalCfg
	defer func() { globalCfg = original }()

	globalCfg = nil
	got := Get()
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if len(got.Skip) != 0 {
		t.Fatalf("expected empty skip list, got %v", got.Skip)
	}
}

func TestMerge(t *testing.T) {
	base := &Config{
		Skip:           []string{"AUTH-001"},
		SkipCategories: []string{"container"},
		AllowedPorts:   []int{22, 80},
		CommandTimeout: 30,
	}
	overlay := &Config{
		Skip:           []string{"AUTH-001", "NET-001"},
		SkipCategories: []string{"nfs"},
		AllowedPorts:   []int{80, 443},
		CommandTimeout: 60,
	}

	result := merge(base, overlay)

	// Skip should be deduplicated
	if len(result.Skip) != 2 {
		t.Fatalf("expected 2 skip entries, got %v", result.Skip)
	}
	// Categories merged and deduped
	if len(result.SkipCategories) != 2 {
		t.Fatalf("expected 2 categories, got %v", result.SkipCategories)
	}
	// Ports merged and deduped
	if len(result.AllowedPorts) != 3 {
		t.Fatalf("expected 3 ports, got %v", result.AllowedPorts)
	}
	// Overlay timeout takes precedence
	if result.CommandTimeout != 60 {
		t.Fatalf("expected timeout=60, got %d", result.CommandTimeout)
	}
}

func TestMergeZeroTimeout(t *testing.T) {
	base := &Config{CommandTimeout: 30}
	overlay := &Config{}

	result := merge(base, overlay)
	if result.CommandTimeout != 30 {
		t.Fatalf("expected base timeout preserved, got %d", result.CommandTimeout)
	}
}

func TestCommandTimeoutField(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"command_timeout":60}`), 0600)

	cfg, err := loadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CommandTimeout != 60 {
		t.Fatalf("expected command_timeout=60, got %d", cfg.CommandTimeout)
	}
}
