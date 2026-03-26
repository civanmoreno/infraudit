package cmd

import (
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/osinfo"
	"github.com/civanmoreno/infraudit/internal/report"
)

// --- mock check types ---

// mockCheck implements check.Check only (no OS/Init/Pkg awareness).
type mockCheck struct {
	id       string
	name     string
	category string
	severity check.Severity
}

func (m mockCheck) ID() string          { return m.id }
func (m mockCheck) Name() string        { return m.name }
func (m mockCheck) Category() string    { return m.category }
func (m mockCheck) Severity() check.Severity { return m.severity }
func (m mockCheck) Description() string { return "mock check" }
func (m mockCheck) Run() check.Result   { return check.Result{Status: check.Pass, Message: "ok"} }

// mockOSCheck implements check.Check + check.OSAware.
type mockOSCheck struct {
	mockCheck
	supportedOS []string
}

func (m mockOSCheck) SupportedOS() []string { return m.supportedOS }

// mockInitCheck implements check.Check + check.InitAware.
type mockInitCheck struct {
	mockCheck
	requiredInit string
}

func (m mockInitCheck) RequiredInit() string { return m.requiredInit }

// mockPkgCheck implements check.Check + check.PkgAware.
type mockPkgCheck struct {
	mockCheck
	requiredPkgManager string
}

func (m mockPkgCheck) RequiredPkgManager() string { return m.requiredPkgManager }

// --- checkOSCompat tests ---

func TestCheckOSCompat_OSAware_Match(t *testing.T) {
	c := mockOSCheck{
		mockCheck:   mockCheck{id: "T-001"},
		supportedOS: []string{"debian"},
	}
	osi := osinfo.Info{Family: osinfo.Debian}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for matching OS, got %q", reason)
	}
}

func TestCheckOSCompat_OSAware_Mismatch(t *testing.T) {
	c := mockOSCheck{
		mockCheck:   mockCheck{id: "T-002"},
		supportedOS: []string{"debian"},
	}
	osi := osinfo.Info{Family: osinfo.RedHat}
	reason := checkOSCompat(c, osi)
	if reason == "" {
		t.Error("expected non-empty reason for mismatched OS")
	}
}

func TestCheckOSCompat_OSAware_EmptySlice(t *testing.T) {
	c := mockOSCheck{
		mockCheck:   mockCheck{id: "T-003"},
		supportedOS: []string{},
	}
	osi := osinfo.Info{Family: osinfo.Alpine}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for empty SupportedOS, got %q", reason)
	}
}

func TestCheckOSCompat_OSAware_MultipleMatch(t *testing.T) {
	c := mockOSCheck{
		mockCheck:   mockCheck{id: "T-004"},
		supportedOS: []string{"debian", "redhat", "alpine"},
	}
	osi := osinfo.Info{Family: osinfo.RedHat}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason when OS is in list, got %q", reason)
	}
}

func TestCheckOSCompat_InitAware_Match(t *testing.T) {
	c := mockInitCheck{
		mockCheck:    mockCheck{id: "T-010"},
		requiredInit: "systemd",
	}
	osi := osinfo.Info{InitSystem: osinfo.Systemd}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for matching init, got %q", reason)
	}
}

func TestCheckOSCompat_InitAware_Mismatch(t *testing.T) {
	c := mockInitCheck{
		mockCheck:    mockCheck{id: "T-011"},
		requiredInit: "systemd",
	}
	osi := osinfo.Info{InitSystem: osinfo.OpenRC}
	reason := checkOSCompat(c, osi)
	if reason == "" {
		t.Error("expected non-empty reason for mismatched init system")
	}
}

func TestCheckOSCompat_InitAware_Empty(t *testing.T) {
	c := mockInitCheck{
		mockCheck:    mockCheck{id: "T-012"},
		requiredInit: "",
	}
	osi := osinfo.Info{InitSystem: osinfo.OpenRC}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for empty RequiredInit, got %q", reason)
	}
}

func TestCheckOSCompat_PkgAware_Match(t *testing.T) {
	c := mockPkgCheck{
		mockCheck:          mockCheck{id: "T-020"},
		requiredPkgManager: "apt",
	}
	osi := osinfo.Info{PkgManager: osinfo.Apt}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for matching pkg manager, got %q", reason)
	}
}

func TestCheckOSCompat_PkgAware_Mismatch(t *testing.T) {
	c := mockPkgCheck{
		mockCheck:          mockCheck{id: "T-021"},
		requiredPkgManager: "apt",
	}
	osi := osinfo.Info{PkgManager: osinfo.Dnf}
	reason := checkOSCompat(c, osi)
	if reason == "" {
		t.Error("expected non-empty reason for mismatched pkg manager")
	}
}

func TestCheckOSCompat_PkgAware_Empty(t *testing.T) {
	c := mockPkgCheck{
		mockCheck:          mockCheck{id: "T-022"},
		requiredPkgManager: "",
	}
	osi := osinfo.Info{PkgManager: osinfo.Dnf}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for empty RequiredPkgManager, got %q", reason)
	}
}

func TestCheckOSCompat_NoAwareness(t *testing.T) {
	c := mockCheck{id: "T-030"}
	osi := osinfo.Info{
		Family:     osinfo.Arch,
		InitSystem: osinfo.OpenRC,
		PkgManager: osinfo.Pacman,
	}
	if reason := checkOSCompat(c, osi); reason != "" {
		t.Errorf("expected empty reason for plain check, got %q", reason)
	}
}

// --- addResult tests ---

func TestAddResult_SkippedIncrementsCounter(t *testing.T) {
	rpt := &report.Report{}
	c := mockCheck{id: "T-100", name: "skip test", category: "test", severity: check.Medium}
	r := check.Result{Status: check.Skipped, Message: "not applicable"}

	addResult(rpt, c, r, -1, nil)

	if rpt.Summary.Skipped != 1 {
		t.Errorf("expected Skipped=1, got %d", rpt.Summary.Skipped)
	}
	if rpt.Summary.Total != 1 {
		t.Errorf("expected Total=1, got %d", rpt.Summary.Total)
	}
}

func TestAddResult_PassIncrementsCounter(t *testing.T) {
	rpt := &report.Report{}
	c := mockCheck{id: "T-101", name: "pass test", category: "test", severity: check.Low}
	r := check.Result{Status: check.Pass, Message: "all good"}

	addResult(rpt, c, r, -1, nil)

	if rpt.Summary.Passed != 1 {
		t.Errorf("expected Passed=1, got %d", rpt.Summary.Passed)
	}
	if rpt.Summary.Total != 1 {
		t.Errorf("expected Total=1, got %d", rpt.Summary.Total)
	}
	if len(rpt.Entries) != 1 {
		t.Errorf("expected 1 displayed entry, got %d", len(rpt.Entries))
	}
}

func TestAddResult_WarnIncrementsCounter(t *testing.T) {
	rpt := &report.Report{}
	c := mockCheck{id: "T-102", name: "warn test", category: "test", severity: check.Medium}
	r := check.Result{Status: check.Warn, Message: "warning"}

	addResult(rpt, c, r, -1, nil)

	if rpt.Summary.Warnings != 1 {
		t.Errorf("expected Warnings=1, got %d", rpt.Summary.Warnings)
	}
}

func TestAddResult_FailIncrementsCounter(t *testing.T) {
	rpt := &report.Report{}
	c := mockCheck{id: "T-103", name: "fail test", category: "test", severity: check.High}
	r := check.Result{Status: check.Fail, Message: "failure"}

	addResult(rpt, c, r, -1, nil)

	if rpt.Summary.Failures != 1 {
		t.Errorf("expected Failures=1, got %d", rpt.Summary.Failures)
	}
}

func TestAddResult_ErrorIncrementsCounter(t *testing.T) {
	rpt := &report.Report{}
	c := mockCheck{id: "T-104", name: "error test", category: "test", severity: check.Critical}
	r := check.Result{Status: check.Error, Message: "error"}

	addResult(rpt, c, r, -1, nil)

	if rpt.Summary.Errors != 1 {
		t.Errorf("expected Errors=1, got %d", rpt.Summary.Errors)
	}
}

func TestAddResult_StatusFilter_SkippedOnly(t *testing.T) {
	rpt := &report.Report{}
	c := mockCheck{id: "T-110", name: "filter test", category: "test", severity: check.Medium}
	statusFilter := map[string]bool{"SKIPPED": true}

	// Add a Pass result -- should be counted but not displayed
	addResult(rpt, c, check.Result{Status: check.Pass, Message: "ok"}, -1, statusFilter)
	if rpt.Summary.Passed != 1 {
		t.Errorf("expected Passed=1, got %d", rpt.Summary.Passed)
	}
	if len(rpt.Entries) != 0 {
		t.Errorf("expected 0 displayed entries for PASS when filter=SKIPPED, got %d", len(rpt.Entries))
	}

	// Add a Skipped result -- should be counted and displayed
	c2 := mockCheck{id: "T-111", name: "skipped one", category: "test", severity: check.Medium}
	addResult(rpt, c2, check.Result{Status: check.Skipped, Message: "skipped"}, -1, statusFilter)
	if rpt.Summary.Skipped != 1 {
		t.Errorf("expected Skipped=1, got %d", rpt.Summary.Skipped)
	}
	if len(rpt.Entries) != 1 {
		t.Errorf("expected 1 displayed entry for SKIPPED, got %d", len(rpt.Entries))
	}
}

func TestAddResult_SeverityFilter(t *testing.T) {
	rpt := &report.Report{}

	// Low-severity check should be filtered when min is High
	cLow := mockCheck{id: "T-120", name: "low sev", category: "test", severity: check.Low}
	addResult(rpt, cLow, check.Result{Status: check.Fail, Message: "fail"}, check.High, nil)

	if rpt.Summary.Failures != 1 {
		t.Errorf("expected Failures=1 (still counted), got %d", rpt.Summary.Failures)
	}
	if len(rpt.Entries) != 0 {
		t.Errorf("expected 0 displayed entries for Low when min=High, got %d", len(rpt.Entries))
	}

	// High-severity check should pass the filter
	cHigh := mockCheck{id: "T-121", name: "high sev", category: "test", severity: check.High}
	addResult(rpt, cHigh, check.Result{Status: check.Fail, Message: "fail"}, check.High, nil)

	if rpt.Summary.Failures != 2 {
		t.Errorf("expected Failures=2, got %d", rpt.Summary.Failures)
	}
	if len(rpt.Entries) != 1 {
		t.Errorf("expected 1 displayed entry for High when min=High, got %d", len(rpt.Entries))
	}
}

func TestAddResult_SeverityAndStatusFilterCombined(t *testing.T) {
	rpt := &report.Report{}
	statusFilter := map[string]bool{"FAIL": true}

	// High severity + PASS status: passes severity but not status filter
	cHigh := mockCheck{id: "T-130", name: "high pass", category: "test", severity: check.High}
	addResult(rpt, cHigh, check.Result{Status: check.Pass, Message: "ok"}, check.Medium, statusFilter)

	if len(rpt.Entries) != 0 {
		t.Errorf("expected 0 displayed entries (status filtered), got %d", len(rpt.Entries))
	}

	// High severity + FAIL status: passes both filters
	cHigh2 := mockCheck{id: "T-131", name: "high fail", category: "test", severity: check.High}
	addResult(rpt, cHigh2, check.Result{Status: check.Fail, Message: "fail"}, check.Medium, statusFilter)

	if len(rpt.Entries) != 1 {
		t.Errorf("expected 1 displayed entry, got %d", len(rpt.Entries))
	}
}

func TestAddResult_AllEntriesAlwaysPopulated(t *testing.T) {
	rpt := &report.Report{}
	statusFilter := map[string]bool{"FAIL": true}

	c := mockCheck{id: "T-140", name: "pass check", category: "test", severity: check.Low}
	addResult(rpt, c, check.Result{Status: check.Pass, Message: "ok"}, check.High, statusFilter)

	// Even though both filters exclude this, AllEntries should have it
	if len(rpt.AllEntries) != 1 {
		t.Errorf("expected 1 AllEntries entry, got %d", len(rpt.AllEntries))
	}
	if len(rpt.Entries) != 0 {
		t.Errorf("expected 0 displayed entries, got %d", len(rpt.Entries))
	}
}
