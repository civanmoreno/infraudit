package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/report"
)

// Policy defines the compliance requirements for an audit.
type Policy struct {
	MinScore     int      `json:"min_score"`
	MaxCritical  int      `json:"max_critical"`
	MaxHigh      int      `json:"max_high"`
	RequiredPass []string `json:"required_pass"`
	Ignore       []string `json:"ignore"`
}

// Violation represents a single policy violation.
type Violation struct {
	Rule    string
	Details string
}

// Result holds the outcome of policy enforcement.
type Result struct {
	Passed     bool
	Violations []Violation
}

// Load reads a policy file (JSON format).
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	// Default max values to -1 (unchecked) if not set
	// JSON unmarshals missing int as 0, so we use a wrapper
	return &p, nil
}

// FindPolicyFile searches for a policy file in standard locations.
func FindPolicyFile() string {
	candidates := []string{
		".infraudit-policy.json",
		".infraudit-policy.yaml",
	}

	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates,
			home+"/.infraudit-policy.json",
		)
	}

	candidates = append(candidates,
		"/etc/infraudit/policy.json",
	)

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// Enforce checks a report against a policy and returns violations.
func Enforce(p *Policy, r *report.Report) Result {
	result := Result{Passed: true}

	// Build ignore set
	ignoreSet := make(map[string]bool, len(p.Ignore))
	for _, id := range p.Ignore {
		ignoreSet[id] = true
	}

	// Check minimum score
	if p.MinScore > 0 && r.Summary.Score < p.MinScore {
		result.Passed = false
		result.Violations = append(result.Violations, Violation{
			Rule:    "min_score",
			Details: fmt.Sprintf("Score %d is below minimum %d", r.Summary.Score, p.MinScore),
		})
	}

	// Count critical and high findings (excluding ignored)
	var criticalCount, highCount int
	for _, e := range r.AllEntries {
		if ignoreSet[e.ID] || e.Status == "PASS" {
			continue
		}
		switch e.Severity {
		case "CRITICAL":
			if e.Status == "FAIL" || e.Status == "ERROR" {
				criticalCount++
			}
		case "HIGH":
			if e.Status == "FAIL" || e.Status == "ERROR" {
				highCount++
			}
		}
	}

	if p.MaxCritical >= 0 && criticalCount > p.MaxCritical {
		result.Passed = false
		result.Violations = append(result.Violations, Violation{
			Rule:    "max_critical",
			Details: fmt.Sprintf("%d critical findings (maximum: %d)", criticalCount, p.MaxCritical),
		})
	}

	if p.MaxHigh >= 0 && highCount > p.MaxHigh {
		result.Passed = false
		result.Violations = append(result.Violations, Violation{
			Rule:    "max_high",
			Details: fmt.Sprintf("%d high findings (maximum: %d)", highCount, p.MaxHigh),
		})
	}

	// Check required passes
	if len(p.RequiredPass) > 0 {
		entryMap := make(map[string]report.Entry, len(r.AllEntries))
		for _, e := range r.AllEntries {
			entryMap[e.ID] = e
		}
		for _, reqID := range p.RequiredPass {
			e, exists := entryMap[reqID]
			if !exists {
				result.Passed = false
				result.Violations = append(result.Violations, Violation{
					Rule:    "required_pass",
					Details: fmt.Sprintf("%s: check not found in audit results", reqID),
				})
				continue
			}
			if e.Status != "PASS" {
				result.Passed = false
				result.Violations = append(result.Violations, Violation{
					Rule:    "required_pass",
					Details: fmt.Sprintf("%s: %s (required: PASS)", reqID, e.Status),
				})
			}
		}
	}

	return result
}

// FormatViolations returns a formatted string of all violations.
func FormatViolations(result Result) string {
	if result.Passed {
		return ""
	}
	var sb strings.Builder
	for _, v := range result.Violations {
		fmt.Fprintf(&sb, "  %-16s %s\n", v.Rule, v.Details)
	}
	return sb.String()
}
