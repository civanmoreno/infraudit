package check

import "fmt"

// Severity indicates the risk level of a check finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Status represents the outcome of a check execution.
type Status int

const (
	Pass Status = iota
	Warn
	Fail
	Error
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	case Error:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Result holds the outcome of running a single check.
type Result struct {
	Status      Status
	Message     string
	Remediation string
	Details     map[string]string
}

// Check defines the interface that every audit check must implement.
type Check interface {
	ID() string
	Name() string
	Category() string
	Severity() Severity
	Description() string
	Run() Result
}

// Summary provides a human-readable one-liner for a check result.
func Summary(c Check, r Result) string {
	return fmt.Sprintf("[%s] %s — %s: %s", r.Status, c.ID(), c.Severity(), r.Message)
}
