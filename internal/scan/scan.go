// Package scan integrates with external container image scanners.
package scan

import "context"

// ScanResult holds the minimal parsed output from an image scanner.
type ScanResult struct {
	Scanner      string   // name of the scanner that produced this result
	VulnCount    int      // total vulnerability count (trivy)
	TopCVEs      []string // top N CVE IDs (trivy)
	PackageCount int      // total package count (syft)
	TopPackages  []string // top N package names (syft)
}

// Scanner is implemented by each external scanning tool.
type Scanner interface {
	// Name returns the scanner identifier (e.g. "trivy", "syft").
	Name() string
	// Available reports whether the scanner binary is on PATH.
	Available() bool
	// Scan runs the scanner against imageRef and returns parsed results.
	Scan(ctx context.Context, imageRef string) (ScanResult, error)
}
