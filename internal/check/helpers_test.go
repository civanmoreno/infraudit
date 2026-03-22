package check

import (
	"testing"
	"time"
)

func TestRunCmdSuccess(t *testing.T) {
	out, err := RunCmd(5*time.Second, "echo", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(out); got != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", got)
	}
}

func TestRunCmdTimeout(t *testing.T) {
	_, err := RunCmd(100*time.Millisecond, "sleep", "5")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if got := err.Error(); !contains(got, "timed out") {
		t.Fatalf("expected timeout error, got: %s", got)
	}
}

func TestRunCmdNotFound(t *testing.T) {
	_, err := RunCmd(time.Second, "nonexistent-binary-xyz")
	if err == nil {
		t.Fatal("expected error for missing binary, got nil")
	}
}

func TestRunCmdOkSuccess(t *testing.T) {
	if !RunCmdOk(5*time.Second, "echo", "ok") {
		t.Fatal("expected true for successful command")
	}
}

func TestRunCmdOkFailure(t *testing.T) {
	if RunCmdOk(5*time.Second, "false") {
		t.Fatal("expected false for failing command")
	}
}

func TestReadSysctl(t *testing.T) {
	// /proc/sys/kernel/ostype should exist on Linux
	val := ReadSysctl("/proc/sys/kernel/ostype")
	if val != "Linux" {
		t.Fatalf("expected 'Linux', got %q", val)
	}
}

func TestReadSysctlMissing(t *testing.T) {
	val := ReadSysctl("/proc/sys/nonexistent/path")
	if val != "" {
		t.Fatalf("expected empty string, got %q", val)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstr(s, substr)
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
