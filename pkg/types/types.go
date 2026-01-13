package types

// Severity levels
type Severity string

const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
)

// Finding represents a security issue detected in a resource
type Finding struct {
	RuleID    string   `json:"rule_id"`
	Severity  Severity `json:"severity"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Reason    string   `json:"reason"`
	Impact    string   `json:"impact"`
	Fix       string   `json:"fix"`
}

// ScanResult contains all findings from a scan
type ScanResult struct {
	Findings []Finding
}

// Summary provides aggregated results
type Summary struct {
	High              int `json:"high"`
	Medium            int `json:"medium"`
	ResourcesAffected int `json:"resources_affected"`
	NamespacesAffected int `json:"namespaces_affected"`
}

// OutputFormat defines the output format for results
type OutputFormat string

const (
	FormatHuman OutputFormat = "human"
	FormatJSON  OutputFormat = "json"
)

// ScanOptions configures the scanner behavior
type ScanOptions struct {
	IncludeMedium bool
	OutputFormat  OutputFormat
}

// ExitCode defines standard exit codes
type ExitCode int

const (
	ExitOK         ExitCode = 0 // No findings
	ExitMedium     ExitCode = 1 // Medium risk only
	ExitHigh       ExitCode = 2 // At least one high risk
	ExitError      ExitCode = 3 // Error occurred
)
