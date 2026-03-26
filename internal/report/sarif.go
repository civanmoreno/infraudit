package report

import (
	"encoding/json"
	"io"

	"github.com/civanmoreno/infraudit/internal/version"
)

// SARIF 2.1.0 structures — Static Analysis Results Interchange Format.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       sarifProperties `json:"properties"`
}

type sarifProperties struct {
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIF writes the report in SARIF 2.1.0 format.
func WriteSARIF(w io.Writer, r *Report) error {
	// Build rules from all entries (deduplicated by ID)
	ruleIndex := map[string]int{}
	var rules []sarifRule
	for _, e := range r.Entries {
		if _, exists := ruleIndex[e.ID]; exists {
			continue
		}
		ruleIndex[e.ID] = len(rules)
		rules = append(rules, sarifRule{
			ID:               e.ID,
			Name:             e.Name,
			ShortDescription: sarifMessage{Text: e.Name},
			HelpURI:          "https://civanmoreno.github.io/infraudit/checks.html",
			Properties: sarifProperties{
				SecuritySeverity: severityToScore(e.Severity),
				Tags:             buildTags(e.Category, e.Severity),
			},
		})
	}

	// Build results (only non-PASS entries)
	var results []sarifResult
	for _, e := range r.Entries {
		if e.Status == "PASS" {
			continue
		}
		msg := e.Message
		if e.Remediation != "" {
			msg += ". Remediation: " + e.Remediation
		}
		results = append(results, sarifResult{
			RuleID:  e.ID,
			Level:   statusToLevel(e.Status),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: categoryToPath(e.Category),
						},
						Region: sarifRegion{StartLine: 1},
					},
				},
			},
		})
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           version.Name,
						Version:        version.Version,
						InformationURI: "https://github.com/civanmoreno/infraudit",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// severityToScore maps infraudit severity to SARIF security-severity (CVSS-like 0-10).
func severityToScore(severity string) string {
	switch severity {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "7.5"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "2.5"
	default:
		return "0.0"
	}
}

// statusToLevel maps infraudit status to SARIF level.
func statusToLevel(status string) string {
	switch status {
	case "FAIL":
		return "error"
	case "WARN":
		return "warning"
	case "ERROR":
		return "error"
	default:
		return "note"
	}
}

// categoryToPath returns a representative file path for the category.
// SARIF requires a location; we use the primary config file for each category.
func categoryToPath(category string) string {
	paths := map[string]string{
		"auth":       "etc/ssh/sshd_config",
		"pam":        "etc/pam.d/common-auth",
		"network":    "etc/sysctl.conf",
		"services":   "etc/systemd/system",
		"filesystem": "etc/fstab",
		"logging":    "etc/audit/auditd.conf",
		"packages":   "etc/apt/sources.list",
		"hardening":  "etc/sysctl.d/99-security.conf",
		"boot":       "boot/grub/grub.cfg",
		"cron":       "etc/crontab",
		"crypto":     "etc/ssl/openssl.cnf",
		"secrets":    "etc/environment",
		"container":  "etc/docker/daemon.json",
		"rlimit":     "etc/security/limits.conf",
		"nfs":        "etc/exports",
		"malware":    "etc/clamav/clamd.conf",
		"backup":     "etc/cron.d/backup",
	}
	if p, ok := paths[category]; ok {
		return p
	}
	return "etc/" + category
}

// buildTags creates SARIF tags for a check.
func buildTags(category, severity string) []string {
	return []string{"security", category, severity}
}
