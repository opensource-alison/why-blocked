package scan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alisonui/why-blocked/internal/execx"
)

const maxTopCVEs = 5

// TrivyScanner wraps the trivy CLI.
type TrivyScanner struct {
	Runner execx.Runner
}

func (s *TrivyScanner) Name() string { return "trivy" }

func (s *TrivyScanner) Available() bool {
	_, _, err := s.Runner.Run(context.Background(), "trivy", []string{"--version"}, nil)
	return err == nil
}

func (s *TrivyScanner) Scan(ctx context.Context, imageRef string) (ScanResult, error) {
	stdout, stderr, err := s.Runner.Run(ctx, "trivy", []string{
		"image", "--format", "json", "--quiet", imageRef,
	}, nil)
	if err != nil {
		return ScanResult{}, fmt.Errorf("trivy: %w: %s", err, stderr)
	}
	return parseTrivyJSON(stdout)
}

// trivyOutput matches the minimal shape of trivy's JSON report.
type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
}

func parseTrivyJSON(data []byte) (ScanResult, error) {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return ScanResult{}, fmt.Errorf("trivy: parsing output: %w", err)
	}

	var allCVEs []string
	for _, r := range out.Results {
		for _, v := range r.Vulnerabilities {
			allCVEs = append(allCVEs, v.VulnerabilityID)
		}
	}

	top := allCVEs
	if len(top) > maxTopCVEs {
		top = top[:maxTopCVEs]
	}

	return ScanResult{
		Scanner:   "trivy",
		VulnCount: len(allCVEs),
		TopCVEs:   top,
	}, nil
}
