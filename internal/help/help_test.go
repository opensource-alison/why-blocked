package help

import (
	"os"
	"strings"
	"testing"

	"github.com/alisonui/why-blocked/internal/ui"
)

// TestMain disables colors globally for all tests to ensure consistent output
func TestMain(m *testing.M) {
	ui.SetEnabled(false)
	os.Exit(m.Run())
}

func TestPrintGlobalUsage(t *testing.T) {
	got := PrintGlobalUsage()
	if got == "" {
		t.Error("PrintGlobalUsage() returned empty string")
	}
	if !strings.Contains(got, "kubectl-why") {
		t.Error("PrintGlobalUsage() should contain 'kubectl-why'")
	}
	if !strings.Contains(got, "LEARN MORE") {
		t.Error("PrintGlobalUsage() should contain 'LEARN MORE' section")
	}
	if !strings.Contains(got, "EXAMPLES") {
		t.Error("PrintGlobalUsage() should contain 'EXAMPLES' section")
	}
	if !strings.Contains(got, "help") {
		t.Error("PrintGlobalUsage() should mention 'help' command")
	}
}

func TestPrintMockUsage(t *testing.T) {
	got := PrintMockUsage()
	if got == "" {
		t.Error("PrintMockUsage() returned empty string")
	}
	if !strings.Contains(got, "mock create") {
		t.Error("PrintMockUsage() should contain 'mock create'")
	}
}

func TestPrintDecisionUsage(t *testing.T) {
	got := PrintDecisionUsage()
	if got == "" {
		t.Error("PrintDecisionUsage() returned empty string")
	}
	if !strings.Contains(got, "decision list") {
		t.Error("PrintDecisionUsage() should contain 'decision list'")
	}
	if !strings.Contains(got, "decision get") {
		t.Error("PrintDecisionUsage() should contain 'decision get'")
	}
}

func TestPrintDecisionGetUsage(t *testing.T) {
	got := PrintDecisionGetUsage()
	if got == "" {
		t.Error("PrintDecisionGetUsage() returned empty string")
	}
	if !strings.Contains(got, "decision get <id>") {
		t.Error("PrintDecisionGetUsage() should contain 'decision get <id>'")
	}
}

func TestPrintExplainUsage(t *testing.T) {
	got := PrintExplainUsage()
	if got == "" {
		t.Error("PrintExplainUsage() returned empty string")
	}
	if !strings.Contains(got, "explain") {
		t.Error("PrintExplainUsage() should contain 'explain'")
	}
}

func TestFormatUnknownCommand(t *testing.T) {
	got := FormatUnknownCommand("badcmd")
	if !strings.Contains(got, "badcmd") {
		t.Error("FormatUnknownCommand() should contain the command name")
	}
	if !strings.Contains(got, "Unknown command") {
		t.Error("FormatUnknownCommand() should contain 'Unknown command'")
	}
}

func TestFormatInvalidOutputFormat(t *testing.T) {
	got := FormatInvalidOutputFormat("yaml")
	if !strings.Contains(got, "yaml") {
		t.Error("FormatInvalidOutputFormat() should contain the format name")
	}
	if !strings.Contains(got, "Invalid output format") {
		t.Error("FormatInvalidOutputFormat() should contain 'Invalid output format'")
	}
}

func TestFormatUnknownDecisionSubcommand(t *testing.T) {
	got := FormatUnknownDecisionSubcommand("bad")
	if !strings.Contains(got, "bad") {
		t.Error("FormatUnknownDecisionSubcommand() should contain the subcommand name")
	}
	if !strings.Contains(got, "Unknown decision subcommand") {
		t.Error("FormatUnknownDecisionSubcommand() should contain 'Unknown decision subcommand'")
	}
}

func TestFormatDecisionNotFound(t *testing.T) {
	got := FormatDecisionNotFound("test-id")
	if !strings.Contains(got, "test-id") {
		t.Error("FormatDecisionNotFound() should contain the decision ID")
	}
	if !strings.Contains(got, "not found") {
		t.Error("FormatDecisionNotFound() should contain 'not found'")
	}
}

func TestFormatNoDecisionFound(t *testing.T) {
	got := FormatNoDecisionFound("Deployment", "my-app", "production")
	if !strings.Contains(got, "Deployment") {
		t.Error("FormatNoDecisionFound() should contain the kind")
	}
	if !strings.Contains(got, "my-app") {
		t.Error("FormatNoDecisionFound() should contain the name")
	}
	if !strings.Contains(got, "production") {
		t.Error("FormatNoDecisionFound() should contain the namespace")
	}
}

func TestFormatJSONNotSupported(t *testing.T) {
	got := FormatJSONNotSupported()
	if !strings.Contains(got, "JSON output") {
		t.Error("FormatJSONNotSupported() should mention JSON output")
	}
	if !strings.Contains(got, "not yet supported") {
		t.Error("FormatJSONNotSupported() should mention 'not yet supported'")
	}
}

func TestFormatNoDecisionsWithTip(t *testing.T) {
	got := FormatNoDecisionsWithTip()
	if !strings.Contains(got, "No decisions found") {
		t.Error("FormatNoDecisionsWithTip() should contain 'No decisions found'")
	}
	if !strings.Contains(got, "Tip") {
		t.Error("FormatNoDecisionsWithTip() should contain a tip")
	}
}

func TestRenderHelpIndex(t *testing.T) {
	got := RenderHelpIndex()
	if got == "" {
		t.Error("RenderHelpIndex() returned empty string")
	}
	if !strings.Contains(got, "Help Topics") {
		t.Error("RenderHelpIndex() should contain 'Help Topics'")
	}
	if !strings.Contains(got, "help explain") {
		t.Error("RenderHelpIndex() should mention 'help explain'")
	}
	if !strings.Contains(got, "help flags") {
		t.Error("RenderHelpIndex() should mention 'help flags'")
	}
}

func TestRenderHelpExplain(t *testing.T) {
	got := RenderHelpExplain()
	if got == "" {
		t.Error("RenderHelpExplain() returned empty string")
	}
	if !strings.Contains(got, "explain") {
		t.Error("RenderHelpExplain() should contain 'explain'")
	}
	if !strings.Contains(got, "WHAT IT DOES") {
		t.Error("RenderHelpExplain() should contain 'WHAT IT DOES' section")
	}
}

func TestRenderHelpDecision(t *testing.T) {
	got := RenderHelpDecision()
	if got == "" {
		t.Error("RenderHelpDecision() returned empty string")
	}
	if !strings.Contains(got, "decision") {
		t.Error("RenderHelpDecision() should contain 'decision'")
	}
	if !strings.Contains(got, "list") {
		t.Error("RenderHelpDecision() should mention 'list'")
	}
}

func TestRenderHelpMock(t *testing.T) {
	got := RenderHelpMock()
	if got == "" {
		t.Error("RenderHelpMock() returned empty string")
	}
	if !strings.Contains(got, "mock") {
		t.Error("RenderHelpMock() should contain 'mock'")
	}
}

func TestRenderHelpFlags(t *testing.T) {
	got := RenderHelpFlags()
	if got == "" {
		t.Error("RenderHelpFlags() returned empty string")
	}
	if !strings.Contains(got, "FLAGS") || !strings.Contains(got, "Flags") {
		t.Error("RenderHelpFlags() should contain 'FLAGS' or 'Flags'")
	}
	if !strings.Contains(got, "--dir") {
		t.Error("RenderHelpFlags() should mention '--dir' flag")
	}
	if !strings.Contains(got, "--scan") {
		t.Error("RenderHelpFlags() should mention '--scan' flag")
	}
}

func TestRenderHelpScan(t *testing.T) {
	got := RenderHelpScan()
	if got == "" {
		t.Error("RenderHelpScan() returned empty string")
	}
	if !strings.Contains(got, "scan") || !strings.Contains(got, "Scan") {
		t.Error("RenderHelpScan() should contain 'scan' or 'Scan'")
	}
	if !strings.Contains(got, "trivy") {
		t.Error("RenderHelpScan() should mention 'trivy'")
	}
}

func TestRenderHelpAI(t *testing.T) {
	got := RenderHelpAI()
	if got == "" {
		t.Error("RenderHelpAI() returned empty string")
	}
	if !strings.Contains(got, "AI") {
		t.Error("RenderHelpAI() should contain 'AI'")
	}
	if !strings.Contains(got, "WHY_AI_API_KEY") {
		t.Error("RenderHelpAI() should mention 'WHY_AI_API_KEY'")
	}
}

func TestRenderHelpOutput(t *testing.T) {
	got := RenderHelpOutput()
	if got == "" {
		t.Error("RenderHelpOutput() returned empty string")
	}
	if !strings.Contains(got, "Output") || !strings.Contains(got, "output") {
		t.Error("RenderHelpOutput() should contain 'Output' or 'output'")
	}
	if !strings.Contains(got, "json") {
		t.Error("RenderHelpOutput() should mention 'json'")
	}
}

func TestRenderHelpI18n(t *testing.T) {
	got := RenderHelpI18n()
	if got == "" {
		t.Error("RenderHelpI18n() returned empty string")
	}
	if !strings.Contains(got, "i18n") || !strings.Contains(got, "Language") {
		t.Error("RenderHelpI18n() should contain 'i18n' or 'Language'")
	}
	if !strings.Contains(got, "ko") && !strings.Contains(got, "Korean") {
		t.Error("RenderHelpI18n() should mention Korean language")
	}
}

func TestFormatUnknownHelpTopic(t *testing.T) {
	got := FormatUnknownHelpTopic("badtopic")
	if !strings.Contains(got, "badtopic") {
		t.Error("FormatUnknownHelpTopic() should contain the topic name")
	}
	if !strings.Contains(got, "Unknown help topic") {
		t.Error("FormatUnknownHelpTopic() should contain 'Unknown help topic'")
	}
}
