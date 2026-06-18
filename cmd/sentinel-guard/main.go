package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/TrippyDev/sentinel/guard/internal/models"
	"github.com/TrippyDev/sentinel/guard/internal/scan"
)

func main() {
	root := flag.String("root", ".", "directory to scan")
	mode := flag.String("mode", "all", "scan mode: all | gha | secrets")
	jsonOut := flag.Bool("json", false, "output findings as JSON")
	flag.Parse()

	var findings []models.Finding
	var err error

	switch *mode {
	case "gha":
		findings, err = scan.GitHubActions(*root)
	case "secrets":
		findings, err = scan.Secrets(*root, 500)
	case "all":
		gha, errGHA := scan.GitHubActions(*root)
		if errGHA != nil {
			err = errGHA
			break
		}
		secrets, errSec := scan.Secrets(*root, 500)
		if errSec != nil {
			err = errSec
			break
		}
		findings = append(gha, secrets...)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (use all, gha, or secrets)\n", *mode)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel-guard error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
			os.Exit(1)
		}
		return
	}

	printHuman(findings)
}

func printHuman(findings []models.Finding) {
	fmt.Println("sentinel-guard :: go hardening layer")
	fmt.Println("----------------------------------------")
	if len(findings) == 0 {
		fmt.Println("status: clean (no Go-guard findings)")
		return
	}
	for _, f := range findings {
		fmt.Printf("\n[%s] %s (%s)\n", f.Severity, f.ID, f.Category)
		if f.File != "" {
			fmt.Printf("  file: %s\n", f.File)
		}
		if f.Signal != "" {
			fmt.Printf("  signal: %s\n", f.Signal)
		}
		fmt.Printf("  %s\n", f.Description)
		if f.Recommendation != "" {
			fmt.Printf("  → %s\n", f.Recommendation)
		}
	}
	fmt.Printf("\n----------------------------------------\n%d finding(s)\n", len(findings))
}