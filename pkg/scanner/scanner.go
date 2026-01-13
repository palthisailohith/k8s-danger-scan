package scanner

import (
	"github.com/palthisailohith/k8s-danger-scan/pkg/parser"
	"github.com/palthisailohith/k8s-danger-scan/pkg/rules"
	"github.com/palthisailohith/k8s-danger-scan/pkg/types"
)

// Scanner performs security scans on Kubernetes resources
type Scanner struct {
	rules   []rules.Rule
	options types.ScanOptions
}

// NewScanner creates a new scanner with the given options
func NewScanner(options types.ScanOptions) *Scanner {
	return &Scanner{
		rules:   rules.AllRules(),
		options: options,
	}
}

// Scan scans the given resources and returns findings
func (s *Scanner) Scan(resources []parser.K8sResource) types.ScanResult {
	var findings []types.Finding

	for _, resource := range resources {
		// Skip unsupported resource kinds
		if !parser.IsSupportedKind(resource.Kind) {
			continue
		}

		// Apply all rules to this resource
		for _, rule := range s.rules {
			ruleFindings := rule(resource)
			findings = append(findings, ruleFindings...)
		}
	}

	// Filter by severity if needed
	if !s.options.IncludeMedium {
		findings = filterHighOnly(findings)
	}

	return types.ScanResult{
		Findings: findings,
	}
}

// Diff compares old and new resources and returns only newly introduced findings
func (s *Scanner) Diff(oldResources, newResources []parser.K8sResource) types.ScanResult {
	// Scan both sets
	oldFindings := s.Scan(oldResources).Findings
	newFindings := s.Scan(newResources).Findings

	// Build a set of old findings for comparison
	oldFindingsSet := make(map[string]bool)
	for _, f := range oldFindings {
		key := findingKey(f)
		oldFindingsSet[key] = true
	}

	// Filter out findings that existed in old version
	var diffFindings []types.Finding
	for _, f := range newFindings {
		key := findingKey(f)
		if !oldFindingsSet[key] {
			diffFindings = append(diffFindings, f)
		}
	}

	return types.ScanResult{
		Findings: diffFindings,
	}
}

// findingKey creates a unique key for a finding
func findingKey(f types.Finding) string {
	return f.RuleID + "|" + f.Kind + "|" + f.Name + "|" + f.Namespace
}

// filterHighOnly filters findings to only include HIGH severity
func filterHighOnly(findings []types.Finding) []types.Finding {
	var filtered []types.Finding
	for _, f := range findings {
		if f.Severity == types.High {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetSummary calculates summary statistics for findings
func GetSummary(findings []types.Finding) types.Summary {
	summary := types.Summary{}
	resourceSet := make(map[string]bool)
	namespaceSet := make(map[string]bool)

	for _, f := range findings {
		switch f.Severity {
		case types.High:
			summary.High++
		case types.Medium:
			summary.Medium++
		}

		resourceKey := f.Kind + "/" + f.Name
		resourceSet[resourceKey] = true

		if f.Namespace != "" {
			namespaceSet[f.Namespace] = true
		}
	}

	summary.ResourcesAffected = len(resourceSet)
	summary.NamespacesAffected = len(namespaceSet)

	return summary
}

// GetExitCode determines the appropriate exit code based on findings
func GetExitCode(findings []types.Finding) types.ExitCode {
	hasHigh := false
	hasMedium := false

	for _, f := range findings {
		if f.Severity == types.High {
			hasHigh = true
		} else if f.Severity == types.Medium {
			hasMedium = true
		}
	}

	if hasHigh {
		return types.ExitHigh
	}
	if hasMedium {
		return types.ExitMedium
	}
	return types.ExitOK
}
