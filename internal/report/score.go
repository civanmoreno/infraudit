package report

// severityWeight returns the point value for a severity level.
func severityWeight(sev string) int {
	switch sev {
	case "CRITICAL":
		return 10
	case "HIGH":
		return 5
	case "MEDIUM":
		return 3
	case "LOW":
		return 1
	default: // INFO
		return 0
	}
}

// ComputeScore calculates a hardening index (0–100) from report entries.
//
// Each check contributes points based on its severity:
//
//	CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1, INFO=0.
//
// A PASS earns all points, WARN earns half, FAIL earns zero.
// ERROR checks are excluded from the calculation.
// The final score is (earned / possible) × 100, clamped to [0, 100].
func ComputeScore(entries []Entry) int {
	var earned, possible int

	for _, e := range entries {
		w := severityWeight(e.Severity)
		if w == 0 {
			continue // INFO checks don't affect score
		}
		if e.Status == "ERROR" {
			continue // can't evaluate, exclude
		}

		possible += w
		switch e.Status {
		case "PASS":
			earned += w
		case "WARN":
			earned += w / 2
		}
		// FAIL earns 0
	}

	if possible == 0 {
		return 100 // no scorable checks → perfect
	}

	score := earned * 100 / possible
	if score > 100 {
		score = 100
	}
	return score
}

// ScoreGrade returns a letter grade for the hardening index.
func ScoreGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
