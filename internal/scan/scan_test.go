package scan

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/alisonui/why-blocked/internal/execx"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("loading fixture %s: %v", name, err)
	}
	return data
}

// --- Trivy ---

func TestTrivyScanner_Name(t *testing.T) {
	s := &TrivyScanner{Runner: execx.NewFakeRunner()}
	if s.Name() != "trivy" {
		t.Errorf("Name() = %q, want %q", s.Name(), "trivy")
	}
}

func TestTrivyScanner_Available(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		fake := execx.NewFakeRunner(execx.FakeResult{Stdout: []byte("0.50.0")})
		s := &TrivyScanner{Runner: fake}
		if !s.Available() {
			t.Error("Available() = false, want true")
		}
		if fake.Calls[0].Args[0] != "--version" {
			t.Errorf("expected --version arg, got %v", fake.Calls[0].Args)
		}
	})
	t.Run("not found", func(t *testing.T) {
		fake := execx.NewFakeRunner(execx.FakeResult{Err: fmt.Errorf("not found")})
		s := &TrivyScanner{Runner: fake}
		if s.Available() {
			t.Error("Available() = true, want false")
		}
	})
}

func TestTrivyScanner_Scan(t *testing.T) {
	fixture := loadFixture(t, "trivy.json")
	fake := execx.NewFakeRunner(execx.FakeResult{Stdout: fixture})
	s := &TrivyScanner{Runner: fake}

	result, err := s.Scan(context.Background(), "nginx:1.25")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Verify command invocation
	c := fake.Calls[0]
	if c.Name != "trivy" {
		t.Errorf("command = %q, want trivy", c.Name)
	}
	if len(c.Args) < 4 || c.Args[0] != "image" || c.Args[len(c.Args)-1] != "nginx:1.25" {
		t.Errorf("args = %v", c.Args)
	}

	if result.Scanner != "trivy" {
		t.Errorf("Scanner = %q", result.Scanner)
	}
	if result.VulnCount != 4 {
		t.Errorf("VulnCount = %d, want 4", result.VulnCount)
	}
	if len(result.TopCVEs) != 4 {
		t.Fatalf("len(TopCVEs) = %d, want 4", len(result.TopCVEs))
	}
	if result.TopCVEs[0] != "CVE-2023-44487" {
		t.Errorf("TopCVEs[0] = %q", result.TopCVEs[0])
	}
}

func TestTrivyScanner_Scan_Clean(t *testing.T) {
	fixture := loadFixture(t, "trivy_clean.json")
	fake := execx.NewFakeRunner(execx.FakeResult{Stdout: fixture})
	s := &TrivyScanner{Runner: fake}

	result, err := s.Scan(context.Background(), "nginx:1.25")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.VulnCount != 0 {
		t.Errorf("VulnCount = %d, want 0", result.VulnCount)
	}
	if result.TopCVEs != nil {
		t.Errorf("TopCVEs = %v, want nil", result.TopCVEs)
	}
}

func TestTrivyScanner_Scan_ExecError(t *testing.T) {
	fake := execx.NewFakeRunner(execx.FakeResult{
		Stderr: []byte("connection refused"),
		Err:    fmt.Errorf("exit 1"),
	})
	s := &TrivyScanner{Runner: fake}

	_, err := s.Scan(context.Background(), "nginx:1.25")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrivyScanner_Scan_TopCVEsCapped(t *testing.T) {
	// Build a fixture with more than maxTopCVEs vulnerabilities.
	result, err := parseTrivyJSON([]byte(`{
		"Results": [{"Vulnerabilities": [
			{"VulnerabilityID": "CVE-1"},
			{"VulnerabilityID": "CVE-2"},
			{"VulnerabilityID": "CVE-3"},
			{"VulnerabilityID": "CVE-4"},
			{"VulnerabilityID": "CVE-5"},
			{"VulnerabilityID": "CVE-6"},
			{"VulnerabilityID": "CVE-7"}
		]}]}
	`))
	if err != nil {
		t.Fatalf("parseTrivyJSON error = %v", err)
	}
	if result.VulnCount != 7 {
		t.Errorf("VulnCount = %d, want 7", result.VulnCount)
	}
	if len(result.TopCVEs) != maxTopCVEs {
		t.Errorf("len(TopCVEs) = %d, want %d", len(result.TopCVEs), maxTopCVEs)
	}
}

// --- Syft ---

func TestSyftScanner_Name(t *testing.T) {
	s := &SyftScanner{Runner: execx.NewFakeRunner()}
	if s.Name() != "syft" {
		t.Errorf("Name() = %q, want %q", s.Name(), "syft")
	}
}

func TestSyftScanner_Available(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		fake := execx.NewFakeRunner(execx.FakeResult{Stdout: []byte("1.0.0")})
		s := &SyftScanner{Runner: fake}
		if !s.Available() {
			t.Error("Available() = false, want true")
		}
	})
	t.Run("not found", func(t *testing.T) {
		fake := execx.NewFakeRunner(execx.FakeResult{Err: fmt.Errorf("not found")})
		s := &SyftScanner{Runner: fake}
		if s.Available() {
			t.Error("Available() = true, want false")
		}
	})
}

func TestSyftScanner_Scan(t *testing.T) {
	fixture := loadFixture(t, "syft.json")
	fake := execx.NewFakeRunner(execx.FakeResult{Stdout: fixture})
	s := &SyftScanner{Runner: fake}

	result, err := s.Scan(context.Background(), "nginx:1.25")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Verify command invocation
	c := fake.Calls[0]
	if c.Name != "syft" {
		t.Errorf("command = %q, want syft", c.Name)
	}
	if len(c.Args) < 3 || c.Args[0] != "nginx:1.25" {
		t.Errorf("args = %v", c.Args)
	}

	if result.Scanner != "syft" {
		t.Errorf("Scanner = %q", result.Scanner)
	}
	if result.PackageCount != 6 {
		t.Errorf("PackageCount = %d, want 6", result.PackageCount)
	}
	if len(result.TopPackages) != 5 {
		t.Fatalf("len(TopPackages) = %d, want 5", len(result.TopPackages))
	}
	if result.TopPackages[0] != "openssl" {
		t.Errorf("TopPackages[0] = %q", result.TopPackages[0])
	}
}

func TestSyftScanner_Scan_Empty(t *testing.T) {
	fixture := loadFixture(t, "syft_empty.json")
	fake := execx.NewFakeRunner(execx.FakeResult{Stdout: fixture})
	s := &SyftScanner{Runner: fake}

	result, err := s.Scan(context.Background(), "scratch")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.PackageCount != 0 {
		t.Errorf("PackageCount = %d, want 0", result.PackageCount)
	}
	if len(result.TopPackages) != 0 {
		t.Errorf("TopPackages = %v, want empty", result.TopPackages)
	}
}

func TestSyftScanner_Scan_ExecError(t *testing.T) {
	fake := execx.NewFakeRunner(execx.FakeResult{
		Stderr: []byte("image not found"),
		Err:    fmt.Errorf("exit 1"),
	})
	s := &SyftScanner{Runner: fake}

	_, err := s.Scan(context.Background(), "nginx:1.25")
	if err == nil {
		t.Fatal("expected error")
	}
}
