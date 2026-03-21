package check

import (
	"testing"
)

// stubCheck is a minimal Check implementation for testing.
type stubCheck struct {
	id          string
	name        string
	category    string
	severity    Severity
	description string
	result      Result
}

func (s *stubCheck) ID() string          { return s.id }
func (s *stubCheck) Name() string        { return s.name }
func (s *stubCheck) Category() string    { return s.category }
func (s *stubCheck) Severity() Severity  { return s.severity }
func (s *stubCheck) Description() string { return s.description }
func (s *stubCheck) Run() Result         { return s.result }

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{Info, "INFO"},
		{Low, "LOW"},
		{Medium, "MEDIUM"},
		{High, "HIGH"},
		{Critical, "CRITICAL"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		st   Status
		want string
	}{
		{Pass, "PASS"},
		{Warn, "WARN"},
		{Fail, "FAIL"},
		{Error, "ERROR"},
	}
	for _, tt := range tests {
		if got := tt.st.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", tt.st, got, tt.want)
		}
	}
}

func TestSummary(t *testing.T) {
	c := &stubCheck{id: "AUTH-001", severity: High}
	r := Result{Status: Fail, Message: "root login enabled"}
	got := Summary(c, r)
	want := "[FAIL] AUTH-001 — HIGH: root login enabled"
	if got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
}

func TestRegistry(t *testing.T) {
	Reset()
	defer Reset()

	c1 := &stubCheck{id: "AUTH-001", category: "auth"}
	c2 := &stubCheck{id: "NET-001", category: "network"}
	c3 := &stubCheck{id: "AUTH-002", category: "auth"}

	Register(c1)
	Register(c2)
	Register(c3)

	all := All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d checks, want 3", len(all))
	}

	auth := ByCategory("auth")
	if len(auth) != 2 {
		t.Fatalf("ByCategory(auth) returned %d checks, want 2", len(auth))
	}

	net := ByCategory("network")
	if len(net) != 1 {
		t.Fatalf("ByCategory(network) returned %d checks, want 1", len(net))
	}

	none := ByCategory("nonexistent")
	if len(none) != 0 {
		t.Fatalf("ByCategory(nonexistent) returned %d checks, want 0", len(none))
	}
}

func TestCategories(t *testing.T) {
	Reset()
	defer Reset()

	Register(&stubCheck{id: "A", category: "auth"})
	Register(&stubCheck{id: "B", category: "network"})
	Register(&stubCheck{id: "C", category: "auth"})

	cats := Categories()
	if len(cats) != 2 {
		t.Fatalf("Categories() returned %d, want 2", len(cats))
	}
}
