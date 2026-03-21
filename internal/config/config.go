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

// Load reads config from the first file found in the search paths.
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

	for _, p := range paths {
		cfg, err := loadFile(p)
		if err == nil {
			return cfg
		}
	}

	return &Config{}
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
