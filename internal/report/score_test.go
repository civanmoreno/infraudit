package report

import "testing"

func TestComputeScore_AllPass(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "PASS"},
		{Severity: "HIGH", Status: "PASS"},
		{Severity: "MEDIUM", Status: "PASS"},
	}
	score := ComputeScore(entries)
	if score != 100 {
		t.Fatalf("expected 100, got %d", score)
	}
}

func TestComputeScore_AllFail(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "FAIL"},
		{Severity: "HIGH", Status: "FAIL"},
	}
	score := ComputeScore(entries)
	if score != 0 {
		t.Fatalf("expected 0, got %d", score)
	}
}

func TestComputeScore_Mixed(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "PASS"}, // 10/10
		{Severity: "HIGH", Status: "WARN"},     // 2/5
		{Severity: "MEDIUM", Status: "FAIL"},   // 0/3
		{Severity: "LOW", Status: "PASS"},      // 1/1
	}
	// earned=13, possible=19 → 13*100/19 = 68
	score := ComputeScore(entries)
	if score != 68 {
		t.Fatalf("expected 68, got %d", score)
	}
}

func TestComputeScore_ErrorsExcluded(t *testing.T) {
	entries := []Entry{
		{Severity: "CRITICAL", Status: "PASS"},
		{Severity: "HIGH", Status: "ERROR"},
	}
	// Only CRITICAL counts: 10/10 = 100
	score := ComputeScore(entries)
	if score != 100 {
		t.Fatalf("expected 100, got %d", score)
	}
}

func TestComputeScore_InfoIgnored(t *testing.T) {
	entries := []Entry{
		{Severity: "INFO", Status: "FAIL"},
		{Severity: "INFO", Status: "PASS"},
	}
	// INFO has weight 0, no scorable checks → 100
	score := ComputeScore(entries)
	if score != 100 {
		t.Fatalf("expected 100, got %d", score)
	}
}

func TestComputeScore_Empty(t *testing.T) {
	score := ComputeScore(nil)
	if score != 100 {
		t.Fatalf("expected 100, got %d", score)
	}
}

func TestScoreGrade(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"}, {95, "A"}, {90, "A"},
		{89, "B"}, {80, "B"},
		{79, "C"}, {70, "C"},
		{69, "D"}, {60, "D"},
		{59, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		got := ScoreGrade(tt.score)
		if got != tt.grade {
			t.Errorf("ScoreGrade(%d) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}
