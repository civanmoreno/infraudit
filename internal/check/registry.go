package check

import "sync"

var (
	mu       sync.Mutex
	registry []Check
)

// Register adds a check to the global registry.
// Checks call this from their init() functions for autodiscovery.
func Register(c Check) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, c)
}

// All returns every registered check.
func All() []Check {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Check, len(registry))
	copy(out, registry)
	return out
}

// ByCategory returns only checks matching the given category.
func ByCategory(category string) []Check {
	mu.Lock()
	defer mu.Unlock()
	var out []Check
	for _, c := range registry {
		if c.Category() == category {
			out = append(out, c)
		}
	}
	return out
}

// Categories returns a sorted list of unique category names.
func Categories() []string {
	mu.Lock()
	defer mu.Unlock()
	seen := make(map[string]bool)
	var cats []string
	for _, c := range registry {
		cat := c.Category()
		if !seen[cat] {
			seen[cat] = true
			cats = append(cats, cat)
		}
	}
	return cats
}

// Reset clears the registry. Used only in tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = nil
}
