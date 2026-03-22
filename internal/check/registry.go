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

// ByCategories returns checks matching any of the given categories.
func ByCategories(categories []string) []Check {
	mu.Lock()
	defer mu.Unlock()
	set := make(map[string]bool, len(categories))
	for _, c := range categories {
		set[c] = true
	}
	var out []Check
	for _, c := range registry {
		if set[c.Category()] {
			out = append(out, c)
		}
	}
	return out
}

// ByID returns the check with the given ID, or nil if not found.
func ByID(id string) Check {
	mu.Lock()
	defer mu.Unlock()
	for _, c := range registry {
		if c.ID() == id {
			return c
		}
	}
	return nil
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
