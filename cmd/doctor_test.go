package cmd

import (
	"testing"
)

func TestBoolStatus(t *testing.T) {
	got := boolStatus(true)
	if got == "" {
		t.Error("boolStatus(true) returned empty string")
	}
	got = boolStatus(false)
	if got == "" {
		t.Error("boolStatus(false) returned empty string")
	}
}

func TestCurrentUser(t *testing.T) {
	got := currentUser()
	if got == "" {
		t.Error("currentUser() returned empty string")
	}
}

func TestCountCategories(t *testing.T) {
	// Note: in test context checks may not be registered (imports are in main.go)
	// so we just verify the function doesn't panic
	count := countCategories()
	if count < 0 {
		t.Errorf("countCategories() = %d, want >= 0", count)
	}
}
