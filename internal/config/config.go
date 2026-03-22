package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the infraudit configuration.
type Config struct {
	// Skip specific check IDs
	Skip []string `json:"skip,omitempty"`
	// Skip entire categories
	SkipCategories []string `json:"skip_categories,omitempty"`
	// Whitelist of allowed listening ports (for NET-002)
	AllowedPorts []int `json:"allowed_ports,omitempty"`
	// Whitelist of processes allowed to run as root (for SVC-008)
	AllowedRootProcesses []string `json:"allowed_root_processes,omitempty"`
	// CommandTimeout overrides the default timeout (in seconds) for external commands.
	CommandTimeout int `json:"command_timeout,omitempty"`
}

// Profiles defines pre-built configurations for common server types.
var Profiles = map[string]Config{
	"web-server": {
		SkipCategories: []string{"container", "nfs"},
		AllowedPorts:   []int{22, 80, 443},
	},
	"db-server": {
		SkipCategories: []string{"container", "nfs"},
		AllowedPorts:   []int{22, 3306, 5432, 6379, 27017},
	},
	"container-host": {
		SkipCategories: []string{"nfs"},
		AllowedPorts:   []int{22, 80, 443, 2376},
	},
	"minimal": {
		SkipCategories: []string{"container", "nfs", "malware", "backup"},
		AllowedPorts:   []int{22},
	},
}

// Load reads and merges config from all found files (system → user → local).
func Load() *Config {
	paths := []string{
		"/etc/infraudit/config.json",
	}

	// User config
	home, err := os.UserHomeDir()
	if err == nil {
		paths = append(paths, filepath.Join(home, ".infraudit.json"))
	}

	// Local config
	paths = append(paths, ".infraudit.json")

	result := &Config{}
	for _, p := range paths {
		cfg, err := loadFile(p)
		if err == nil {
			result = merge(result, cfg)
		}
	}

	return result
}

// merge combines base and overlay configs, with overlay values taking precedence.
func merge(base, overlay *Config) *Config {
	result := *base
	result.Skip = dedup(append(result.Skip, overlay.Skip...))
	result.SkipCategories = dedup(append(result.SkipCategories, overlay.SkipCategories...))
	result.AllowedPorts = dedupInt(append(result.AllowedPorts, overlay.AllowedPorts...))
	result.AllowedRootProcesses = dedup(append(result.AllowedRootProcesses, overlay.AllowedRootProcesses...))
	if overlay.CommandTimeout > 0 {
		result.CommandTimeout = overlay.CommandTimeout
	}
	return &result
}

func dedup(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func dedupInt(s []int) []int {
	seen := make(map[int]bool, len(s))
	out := make([]int, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var globalCfg *Config

// Set stores the config for global access by checks.
func Set(c *Config) {
	globalCfg = c
}

// Get returns the globally stored config, or a zero config if none was set.
func Get() *Config {
	if globalCfg == nil {
		return &Config{}
	}
	return globalCfg
}

// ShouldSkip returns true if the check ID or category should be skipped.
func (c *Config) ShouldSkip(id, category string) bool {
	for _, s := range c.Skip {
		if s == id {
			return true
		}
	}
	for _, s := range c.SkipCategories {
		if s == category {
			return true
		}
	}
	return false
}
