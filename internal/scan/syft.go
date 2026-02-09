package scan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alisonui/why-blocked/internal/execx"
)

const maxTopPackages = 5

// SyftScanner wraps the syft CLI.
type SyftScanner struct {
	Runner execx.Runner
}

func (s *SyftScanner) Name() string { return "syft" }

func (s *SyftScanner) Available() bool {
	_, _, err := s.Runner.Run(context.Background(), "syft", []string{"version"}, nil)
	return err == nil
}

func (s *SyftScanner) Scan(ctx context.Context, imageRef string) (ScanResult, error) {
	stdout, stderr, err := s.Runner.Run(ctx, "syft", []string{
		imageRef, "-o", "json",
	}, nil)
	if err != nil {
		return ScanResult{}, fmt.Errorf("syft: %w: %s", err, stderr)
	}
	return parseSyftJSON(stdout)
}

// syftOutput matches the minimal shape of syft's JSON output.
type syftOutput struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftArtifact struct {
	Name string `json:"name"`
}

func parseSyftJSON(data []byte) (ScanResult, error) {
	var out syftOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return ScanResult{}, fmt.Errorf("syft: parsing output: %w", err)
	}

	names := make([]string, len(out.Artifacts))
	for i, a := range out.Artifacts {
		names[i] = a.Name
	}

	top := names
	if len(top) > maxTopPackages {
		top = top[:maxTopPackages]
	}

	return ScanResult{
		Scanner:      "syft",
		PackageCount: len(names),
		TopPackages:  top,
	}, nil
}
