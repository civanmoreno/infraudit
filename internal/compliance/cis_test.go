package compliance

import (
	"testing"
)

func TestControlsByLevelL1(t *testing.T) {
	l1 := ControlsByLevel(L1)
	l2 := ControlsByLevel(L2)

	if len(l1) == 0 {
		t.Fatal("no L1 controls found")
	}
	if len(l2) == 0 {
		t.Fatal("no L2 controls found")
	}
	if len(l2) <= len(l1) {
		t.Errorf("L2 (%d) should have more controls than L1 (%d)", len(l2), len(l1))
	}

	// All L1 controls should also be in L2
	for _, c := range l1 {
		if c.Level > L1 {
			t.Errorf("L1 result contains L2 control: %s", c.CheckID)
		}
	}
}

func TestControlByCheckID(t *testing.T) {
	c := ControlByCheckID("AUTH-001")
	if c == nil {
		t.Fatal("AUTH-001 should have a CIS control")
	}
	if c.Section != "5.2.1" {
		t.Errorf("AUTH-001 section = %q, want 5.2.1", c.Section)
	}
	if c.Level != L1 {
		t.Errorf("AUTH-001 level = %d, want L1", c.Level)
	}
}

func TestControlByCheckIDNotFound(t *testing.T) {
	c := ControlByCheckID("FAKE-999")
	if c != nil {
		t.Error("FAKE-999 should not have a CIS control")
	}
}

func TestNoDuplicateCheckIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, c := range CISControls {
		if seen[c.CheckID] {
			t.Errorf("duplicate check ID in CIS controls: %s", c.CheckID)
		}
		seen[c.CheckID] = true
	}
}

func TestAllControlsHaveRequiredFields(t *testing.T) {
	for _, c := range CISControls {
		if c.CheckID == "" {
			t.Error("control with empty CheckID")
		}
		if c.Section == "" {
			t.Errorf("%s: empty Section", c.CheckID)
		}
		if c.SectionName == "" {
			t.Errorf("%s: empty SectionName", c.CheckID)
		}
		if c.Category == "" {
			t.Errorf("%s: empty Category", c.CheckID)
		}
		if c.Level != L1 && c.Level != L2 {
			t.Errorf("%s: invalid Level %d", c.CheckID, c.Level)
		}
	}
}

func TestCISCategoriesCoverAllControls(t *testing.T) {
	validCats := make(map[string]bool)
	for _, cat := range CISCategories {
		validCats[cat.Number+". "+cat.Name] = true
	}
	for _, c := range CISControls {
		if !validCats[c.Category] {
			t.Errorf("%s has invalid category %q", c.CheckID, c.Category)
		}
	}
}

func TestControlCount(t *testing.T) {
	total := len(CISControls)
	if total < 80 {
		t.Errorf("expected at least 80 CIS controls, got %d", total)
	}
}
