package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/palthisailohith/k8s-danger-scan/pkg/output"
	"github.com/palthisailohith/k8s-danger-scan/pkg/parser"
	"github.com/palthisailohith/k8s-danger-scan/pkg/scanner"
	"github.com/palthisailohith/k8s-danger-scan/pkg/types"
)

const version = "1.0.0"

func printUsage() {
	fmt.Fprintf(os.Stderr, `k8s-danger-scan - Detect catastrophic Kubernetes misconfigurations

Usage:
  k8s-danger-scan scan <path> [flags]        Scan manifest files or directory
  k8s-danger-scan diff <old> <new> [flags]   Compare manifests and show new risks only
  k8s-danger-scan --version                  Show version

Flags:
  --json              Output in JSON format
  --include-medium    Include MEDIUM severity findings (default: HIGH only)

Exit Codes:
  0  No findings
  1  Medium risk only
  2  At least one high risk
  3  Error occurred

Examples:
  k8s-danger-scan scan ./manifests
  k8s-danger-scan scan deployment.yaml --include-medium
  k8s-danger-scan diff old.yaml new.yaml
  k8s-danger-scan scan . --json --include-medium
`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(int(types.ExitError))
	}

	// Handle version flag
	if os.Args[1] == "--version" || os.Args[1] == "-version" {
		fmt.Printf("k8s-danger-scan version %s\n", version)
		os.Exit(0)
	}

	command := os.Args[1]

	// Parse command-specific flags
	var jsonOutput, includeMedium bool
	var paths []string

	switch command {
	case "scan":
		scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
		jsonPtr := scanFlags.Bool("json", false, "Output in JSON format")
		mediumPtr := scanFlags.Bool("include-medium", false, "Include medium severity findings")
		scanFlags.Parse(os.Args[2:])

		jsonOutput = *jsonPtr
		includeMedium = *mediumPtr
		paths = scanFlags.Args()

		if len(paths) < 1 {
			fmt.Fprintln(os.Stderr, "Error: scan requires a path argument")
			fmt.Fprintln(os.Stderr, "Usage: k8s-danger-scan scan <path> [--json] [--include-medium]")
			os.Exit(int(types.ExitError))
		}

	case "diff":
		diffFlags := flag.NewFlagSet("diff", flag.ExitOnError)
		jsonPtr := diffFlags.Bool("json", false, "Output in JSON format")
		mediumPtr := diffFlags.Bool("include-medium", false, "Include medium severity findings")
		diffFlags.Parse(os.Args[2:])

		jsonOutput = *jsonPtr
		includeMedium = *mediumPtr
		paths = diffFlags.Args()

		if len(paths) < 2 {
			fmt.Fprintln(os.Stderr, "Error: diff requires two path arguments")
			fmt.Fprintln(os.Stderr, "Usage: k8s-danger-scan diff <old> <new> [--json] [--include-medium]")
			os.Exit(int(types.ExitError))
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(int(types.ExitError))
	}

	// Create scanner with options
	scanOptions := types.ScanOptions{
		IncludeMedium: includeMedium,
		OutputFormat:  types.FormatHuman,
	}

	if jsonOutput {
		scanOptions.OutputFormat = types.FormatJSON
	}

	s := scanner.NewScanner(scanOptions)

	var result types.ScanResult
	var err error

	switch command {
	case "scan":
		result, err = runScan(s, paths)

	case "diff":
		result, err = runDiff(s, paths[0], paths[1])

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(int(types.ExitError))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(int(types.ExitError))
	}

	// Calculate summary
	summary := scanner.GetSummary(result.Findings)

	// Output results
	formatter := output.NewFormatter(os.Stdout, scanOptions.OutputFormat)
	if err := formatter.Output(result.Findings, summary); err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(int(types.ExitError))
	}

	// Exit with appropriate code
	exitCode := scanner.GetExitCode(result.Findings)
	os.Exit(int(exitCode))
}

// runScan performs a scan on the given paths
func runScan(s *scanner.Scanner, paths []string) (types.ScanResult, error) {
	resources, err := parser.ParseFiles(paths...)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to parse files: %w", err)
	}

	if len(resources) == 0 {
		return types.ScanResult{}, fmt.Errorf("no Kubernetes resources found in specified paths")
	}

	return s.Scan(resources), nil
}

// runDiff performs a diff between old and new manifests
func runDiff(s *scanner.Scanner, oldPath, newPath string) (types.ScanResult, error) {
	oldResources, err := parser.ParseFiles(oldPath)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to parse old manifest: %w", err)
	}

	newResources, err := parser.ParseFiles(newPath)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("failed to parse new manifest: %w", err)
	}

	return s.Diff(oldResources, newResources), nil
}
