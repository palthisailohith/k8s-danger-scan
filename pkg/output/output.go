package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/palthisailohith/k8s-danger-scan/pkg/types"
)

// Formatter handles output formatting
type Formatter struct {
	writer io.Writer
	format types.OutputFormat
}

// NewFormatter creates a new output formatter
func NewFormatter(writer io.Writer, format types.OutputFormat) *Formatter {
	return &Formatter{
		writer: writer,
		format: format,
	}
}

// Output writes the findings and summary using the configured format
func (f *Formatter) Output(findings []types.Finding, summary types.Summary) error {
	switch f.format {
	case types.FormatJSON:
		return f.outputJSON(findings, summary)
	case types.FormatHuman:
		return f.outputHuman(findings, summary)
	default:
		return f.outputHuman(findings, summary)
	}
}

// outputJSON outputs findings in JSON format
func (f *Formatter) outputJSON(findings []types.Finding, summary types.Summary) error {
	output := struct {
		Summary  types.Summary   `json:"summary"`
		Findings []types.Finding `json:"findings"`
	}{
		Summary:  summary,
		Findings: findings,
	}

	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputHuman outputs findings in human-readable format
func (f *Formatter) outputHuman(findings []types.Finding, summary types.Summary) error {
	if len(findings) == 0 {
		fmt.Fprintln(f.writer, "No security issues found.")
		return nil
	}

	// Print each finding
	for i, finding := range findings {
		if i > 0 {
			fmt.Fprintln(f.writer, "")
		}

		fmt.Fprintf(f.writer, "%s RISK\n", finding.Severity)
		fmt.Fprintf(f.writer, "Resource: %s/%s\n", finding.Kind, finding.Name)
		if finding.Namespace != "" {
			fmt.Fprintf(f.writer, "Namespace: %s\n", finding.Namespace)
		}
		fmt.Fprintf(f.writer, "Rule: %s\n", finding.RuleID)
		fmt.Fprintf(f.writer, "Reason: %s\n", finding.Reason)
		fmt.Fprintf(f.writer, "Impact: %s\n", finding.Impact)
		fmt.Fprintf(f.writer, "Fix: %s\n", finding.Fix)
	}

	// Print summary
	fmt.Fprintln(f.writer, "")
	fmt.Fprintln(f.writer, "SUMMARY")
	fmt.Fprintf(f.writer, "High risk: %d\n", summary.High)
	fmt.Fprintf(f.writer, "Medium risk: %d\n", summary.Medium)
	fmt.Fprintf(f.writer, "Resources affected: %d\n", summary.ResourcesAffected)
	if summary.NamespacesAffected > 0 {
		fmt.Fprintf(f.writer, "Namespaces affected: %d\n", summary.NamespacesAffected)
	}

	return nil
}
