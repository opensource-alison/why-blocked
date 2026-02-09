package output

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alisonui/why-blocked/internal/decision"
	"github.com/alisonui/why-blocked/internal/i18n"
	"github.com/alisonui/why-blocked/internal/ui"
)

func TestRenderDecision(t *testing.T) {
	d := decision.SecurityDecision{
		ID:        "test-123",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Deployment blocked due to security violations",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "test-app",
			Namespace: "production",
		},
		Violations: []decision.Violation{
			{
				PolicyID: "POL-001",
				Title:    "Test Violation",
				Severity: decision.SeverityCritical,
				Message:  "This is a test violation message",
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: "spec.field",
						Detail:  "Field detail",
					},
				},
				Fix: []decision.Action{
					{
						Title:  "Fix it",
						Detail: "Apply this fix",
					},
				},
			},
		},
		NextActions: []decision.Action{
			{
				Title:  "Update manifest",
				Detail: "Apply suggested changes",
			},
		},
	}

	output := RenderDecision(d, nil)

	// Verify header section
	if !strings.Contains(output, "WHY: Deployment blocked due to security violations") {
		t.Error("RenderDecision() missing summary in header")
	}
	if !strings.Contains(output, "STATUS: BLOCKED") {
		t.Error("RenderDecision() missing status in header")
	}
	if !strings.Contains(output, "RESOURCE: Deployment/test-app") {
		t.Error("RenderDecision() missing resource in header")
	}
	if !strings.Contains(output, "NAMESPACE: production") {
		t.Error("RenderDecision() missing namespace in header")
	}
	if !strings.Contains(output, "DECISION: test-123") {
		t.Error("RenderDecision() missing decision ID in header")
	}
	if !strings.Contains(output, "TIME: 2026-02-05T16:30:00Z") {
		t.Error("RenderDecision() missing or incorrect timestamp in header")
	}

	// Verify violations section
	if !strings.Contains(output, "VIOLATIONS (1):") {
		t.Error("RenderDecision() missing violations header")
	}
	if !strings.Contains(output, "[CRITICAL] Test Violation") {
		t.Error("RenderDecision() missing violation title with severity")
	}
	if !strings.Contains(output, "This is a test violation message") {
		t.Error("RenderDecision() missing violation message")
	}
	if !strings.Contains(output, "Evidence:") {
		t.Error("RenderDecision() missing evidence section")
	}
	if !strings.Contains(output, "(K8S_FIELD) spec.field: Field detail") {
		t.Error("RenderDecision() missing evidence detail")
	}
	if !strings.Contains(output, "Fix (minimal):") {
		t.Error("RenderDecision() missing fix section")
	}
	if !strings.Contains(output, "Fix it: Apply this fix") {
		t.Error("RenderDecision() missing fix detail")
	}

	// Verify next actions section
	if !strings.Contains(output, "NEXT ACTIONS:") {
		t.Error("RenderDecision() missing next actions header")
	}
	if !strings.Contains(output, "Update manifest: Apply suggested changes") {
		t.Error("RenderDecision() missing next action detail")
	}
}

func TestRenderDecision_NoViolations(t *testing.T) {
	d := decision.SecurityDecision{
		ID:        "test-allowed",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusAllowed,
		Summary:   "Deployment allowed",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "safe-app",
			Namespace: "default",
		},
		Violations:  []decision.Violation{},
		NextActions: []decision.Action{},
	}

	output := RenderDecision(d, nil)

	// Should have header
	if !strings.Contains(output, "WHY: Deployment allowed") {
		t.Error("RenderDecision() missing summary for allowed decision")
	}
	if !strings.Contains(output, "STATUS: ALLOWED") {
		t.Error("RenderDecision() missing status for allowed decision")
	}

	// Should not have violations section
	if strings.Contains(output, "VIOLATIONS") {
		t.Error("RenderDecision() should not show violations section when empty")
	}

	// Should not have next actions section
	if strings.Contains(output, "NEXT ACTIONS") {
		t.Error("RenderDecision() should not show next actions section when empty")
	}
}

func TestRenderDecision_MultipleViolations(t *testing.T) {
	d := decision.SecurityDecision{
		ID:        "test-multi",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Multiple violations",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "test-app",
			Namespace: "default",
		},
		Violations: []decision.Violation{
			{
				PolicyID: "POL-001",
				Title:    "First Violation",
				Severity: decision.SeverityCritical,
				Message:  "First issue",
			},
			{
				PolicyID: "POL-002",
				Title:    "Second Violation",
				Severity: decision.SeverityHigh,
				Message:  "Second issue",
			},
			{
				PolicyID: "POL-003",
				Title:    "Third Violation",
				Severity: decision.SeverityMedium,
				Message:  "Third issue",
			},
		},
	}

	output := RenderDecision(d, nil)

	if !strings.Contains(output, "VIOLATIONS (3):") {
		t.Error("RenderDecision() should show correct violation count")
	}
	if !strings.Contains(output, "1) [CRITICAL] First Violation") {
		t.Error("RenderDecision() missing first violation")
	}
	if !strings.Contains(output, "2) [HIGH] Second Violation") {
		t.Error("RenderDecision() missing second violation")
	}
	if !strings.Contains(output, "3) [MEDIUM] Third Violation") {
		t.Error("RenderDecision() missing third violation")
	}
}

func TestRenderDecision_NextActionsLimit(t *testing.T) {
	actions := []decision.Action{
		{Title: "Action 1"},
		{Title: "Action 2"},
		{Title: "Action 3"},
		{Title: "Action 4"},
		{Title: "Action 5"},
		{Title: "Action 6"},
	}

	d := decision.SecurityDecision{
		ID:        "test-actions",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Test",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "test",
			Namespace: "default",
		},
		NextActions: actions,
	}

	output := RenderDecision(d, nil)

	// Should show first 4 actions
	if !strings.Contains(output, "Action 1") {
		t.Error("RenderDecision() missing action 1")
	}
	if !strings.Contains(output, "Action 4") {
		t.Error("RenderDecision() missing action 4")
	}

	// Should not show 5th and 6th actions (limit is 4)
	if strings.Contains(output, "Action 5") {
		t.Error("RenderDecision() should limit next actions to 4")
	}
	if strings.Contains(output, "Action 6") {
		t.Error("RenderDecision() should limit next actions to 4")
	}
}

func TestRenderDecision_ExampleBlockedDecision(t *testing.T) {
	// Test with the actual example decision to ensure it renders without errors
	d := decision.ExampleBlockedDecision()
	output := RenderDecision(d, nil)

	if output == "" {
		t.Error("RenderDecision() returned empty string for ExampleBlockedDecision")
	}

	// Verify key sections are present
	if !strings.Contains(output, "WHY:") {
		t.Error("RenderDecision() missing WHY section")
	}
	if !strings.Contains(output, "STATUS:") {
		t.Error("RenderDecision() missing STATUS section")
	}
	if !strings.Contains(output, "RESOURCE:") {
		t.Error("RenderDecision() missing RESOURCE section")
	}
	if !strings.Contains(output, "VIOLATIONS") {
		t.Error("RenderDecision() missing VIOLATIONS section")
	}
}

func TestWrapIndent(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		width  int
		indent string
		want   string
	}{
		{
			name:   "short text no wrap",
			text:   "short",
			width:  80,
			indent: "  ",
			want:   "short",
		},
		{
			name:   "text exactly at width",
			text:   strings.Repeat("a", 80),
			width:  80,
			indent: "  ",
			want:   strings.Repeat("a", 80),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapIndent(tt.text, tt.width, tt.indent)
			if got != tt.want {
				t.Errorf("wrapIndent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderDecision_Japanese(t *testing.T) {
	tr, err := i18n.New("ja")
	if err != nil {
		t.Fatalf("i18n.New(ja) error = %v", err)
	}

	d := decision.SecurityDecision{
		ID:        "test-ja",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Deployment blocked",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "test-app",
			Namespace: "production",
		},
		Violations: []decision.Violation{
			{
				PolicyID: "POL-001",
				Title:    "Privileged Container",
				Severity: decision.SeverityCritical,
				Message:  "Container runs as privileged",
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: "spec.containers[0].securityContext.privileged",
						Detail:  "set to true",
					},
				},
				Fix: []decision.Action{
					{Title: "Disable privileged", Detail: "Set privileged: false"},
				},
			},
		},
		NextActions: []decision.Action{
			{Title: "Update manifest", Detail: "Apply patches"},
		},
	}

	out := RenderDecision(d, tr)

	// Labels should be in Japanese
	if !strings.Contains(out, "理由:") {
		t.Error("missing Japanese 'reason' label (理由:)")
	}
	if !strings.Contains(out, "状態:") {
		t.Error("missing Japanese 'status' label (状態:)")
	}
	if !strings.Contains(out, "リソース:") {
		t.Error("missing Japanese 'resource' label (リソース:)")
	}
	if !strings.Contains(out, "違反 (1):") {
		t.Error("missing Japanese 'violations' section header (違反)")
	}
	if !strings.Contains(out, "証拠:") {
		t.Error("missing Japanese 'evidence' label (証拠:)")
	}
	if !strings.Contains(out, "修正 (最小):") {
		t.Error("missing Japanese 'fix' label (修正 (最小):)")
	}
	if !strings.Contains(out, "次のアクション:") {
		t.Error("missing Japanese 'next actions' label (次のアクション:)")
	}

	// K8s field paths must NOT be translated
	if !strings.Contains(out, "spec.containers[0].securityContext.privileged") {
		t.Error("K8s field path should not be translated")
	}
}

func TestRenderDecision_Korean_KeyBased(t *testing.T) {
	tr, err := i18n.New("ko")
	if err != nil {
		t.Fatalf("i18n.New(ko) error = %v", err)
	}

	d := decision.SecurityDecision{
		ID:         "test-ko-keys",
		Timestamp:  time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:    "v1alpha1",
		Status:     decision.StatusBlocked,
		Summary:    "Deployment blocked due to critical security violations",
		SummaryKey: "decision.summary.blocked_critical",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "test-app",
			Namespace: "production",
		},
		Violations: []decision.Violation{
			{
				PolicyID:   "POL-SEC-001",
				Title:      "Privileged Container",
				TitleKey:   "violation.k8s.privileged.title",
				Severity:   decision.SeverityCritical,
				Message:    "Containers must not run as privileged.",
				MessageKey: "violation.k8s.privileged.message",
				MessageArgs: map[string]string{
					"container": "mycontainer",
				},
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: "spec.containers[0].securityContext.privileged",
						Detail:  "set to true",
					},
				},
				Fix: []decision.Action{
					{
						Title:     "Disable privileged mode",
						TitleKey:  "action.fix.disable_privileged.title",
						Detail:    "Set securityContext.privileged: false",
						DetailKey: "action.fix.disable_privileged.detail",
						DetailArgs: map[string]string{
							"container": "mycontainer",
						},
					},
				},
			},
		},
		NextActions: []decision.Action{
			{
				Title:     "Update deployment manifest",
				TitleKey:  "action.next.update_manifest.title",
				Detail:    "Apply the suggested patches.",
				DetailKey: "action.next.update_manifest.detail",
			},
		},
	}

	out := RenderDecision(d, tr)

	// Summary should be translated Korean
	if !strings.Contains(out, "심각한 보안 위반으로 인해 배포가 차단되었습니다") {
		t.Errorf("Summary not translated to Korean.\nGot:\n%s", out)
	}

	// Violation title should be Korean
	if !strings.Contains(out, "특권(Privileged) 컨테이너") {
		t.Errorf("Violation title not translated to Korean.\nGot:\n%s", out)
	}

	// Violation message should contain Korean text with interpolated container name
	// Note: wrapIndent may split lines, so check pieces separately
	if !strings.Contains(out, "특권(privileged) 컨테이너는 허용되지 않습니다") {
		t.Errorf("Violation message missing Korean privileged phrase.\nGot:\n%s", out)
	}
	if !strings.Contains(out, "'mycontainer'") {
		t.Errorf("Violation message missing interpolated container name.\nGot:\n%s", out)
	}

	// Fix title should be Korean
	if !strings.Contains(out, "특권 모드 비활성화") {
		t.Errorf("Fix title not translated to Korean.\nGot:\n%s", out)
	}

	// Fix detail should include interpolated container name in Korean
	if !strings.Contains(out, "'mycontainer' 컨테이너 스펙에서") {
		t.Errorf("Fix detail not translated to Korean with interpolated container.\nGot:\n%s", out)
	}

	// Next action title should be Korean
	if !strings.Contains(out, "배포 매니페스트 업데이트") {
		t.Errorf("Next action title not translated to Korean.\nGot:\n%s", out)
	}

	// Labels should still be Korean
	if !strings.Contains(out, "이유:") {
		t.Error("missing Korean 'reason' label")
	}
	if !strings.Contains(out, "위반 사항 (1):") {
		t.Error("missing Korean 'violations' section header")
	}

	// Evidence should NOT be translated (field paths stay as-is)
	if !strings.Contains(out, "spec.containers[0].securityContext.privileged") {
		t.Error("K8s field path should not be translated")
	}
}

func TestRenderDecision_FallbackWithoutKeys(t *testing.T) {
	// Decision with NO keys should render exactly as before (raw strings)
	d := decision.SecurityDecision{
		ID:        "test-nokeys",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Blocked for testing",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "app",
			Namespace: "default",
		},
		Violations: []decision.Violation{
			{
				PolicyID: "POL-001",
				Title:    "Raw English Title",
				Severity: decision.SeverityHigh,
				Message:  "Raw English message body",
				Fix: []decision.Action{
					{
						Title:  "Raw fix title",
						Detail: "Raw fix detail",
					},
				},
			},
		},
		NextActions: []decision.Action{
			{
				Title:  "Raw action title",
				Detail: "Raw action detail",
			},
		},
	}

	tr, _ := i18n.New("ko")
	out := RenderDecision(d, tr)

	// Without keys, raw strings should appear verbatim even with Korean translator
	if !strings.Contains(out, "Raw English Title") {
		t.Error("Violation title should fall back to raw string when no TitleKey")
	}
	if !strings.Contains(out, "Raw English message body") {
		t.Error("Violation message should fall back to raw string when no MessageKey")
	}
	if !strings.Contains(out, "Raw fix title") {
		t.Error("Fix title should fall back to raw string when no TitleKey")
	}
	if !strings.Contains(out, "Raw action title") {
		t.Error("Next action title should fall back to raw string when no TitleKey")
	}

	// But labels should still be Korean
	if !strings.Contains(out, "이유:") {
		t.Error("Labels should still be Korean even without message keys")
	}
}

func TestRenderDecision_Korean_ImageViolation(t *testing.T) {
	tr, err := i18n.New("ko")
	if err != nil {
		t.Fatalf("i18n.New(ko) error = %v", err)
	}

	d := decision.SecurityDecision{
		ID:        "test-ko-image",
		Timestamp: time.Date(2026, 2, 5, 16, 30, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "blocked",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "web",
			Namespace: "default",
		},
		Violations: []decision.Violation{
			{
				PolicyID:   "POL-SEC-005",
				Title:      "Insecure Image Usage",
				TitleKey:   "violation.image.latest.title",
				Severity:   decision.SeverityHigh,
				Message:    "Uses insecure image.",
				MessageKey: "violation.image.latest.message",
				MessageArgs: map[string]string{
					"image":    "nginx:latest",
					"tag":      "latest",
					"cveCount": "3",
				},
			},
		},
	}

	out := RenderDecision(d, tr)

	// Korean translated title
	if !strings.Contains(out, "안전하지 않은 이미지 사용") {
		t.Errorf("Image violation title not Korean.\nGot:\n%s", out)
	}

	// Korean message with interpolated args
	if !strings.Contains(out, "이미지 'nginx:latest'") {
		t.Errorf("Image violation message missing interpolated image.\nGot:\n%s", out)
	}
	// cveCount is interpolated; wrapping may split the line
	collapsed := collapseWhitespace(out)
	if !strings.Contains(collapsed, "3개의 심각한 CVE가 발견되었습니다") {
		t.Errorf("Image violation message missing interpolated cveCount.\nGot (collapsed):\n%s", collapsed)
	}
}

// collapseWhitespace replaces sequences of whitespace (including newlines) with a single space.
func collapseWhitespace(s string) string {
	var b strings.Builder
	inSpace := false
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			if !inSpace {
				b.WriteRune(' ')
				inSpace = true
			}
		} else {
			b.WriteRune(r)
			inSpace = false
		}
	}
	return b.String()
}

func TestColorSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "CRITICAL"}, // Would be red if colors enabled
		{"HIGH", "HIGH"},         // Would be yellow if colors enabled
		{"MEDIUM", "MEDIUM"},     // Would be cyan if colors enabled
		{"LOW", "LOW"},           // No color
		{"UNKNOWN", "UNKNOWN"},   // No color
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := colorSeverity(tt.severity)
			// With colors disabled (via TestMain), should return plain text
			if got != tt.want {
				t.Errorf("colorSeverity(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestColorSeverity_WithColorsEnabled(t *testing.T) {
	// Temporarily enable colors to verify ANSI codes are added
	ui.SetEnabled(true)
	defer ui.SetEnabled(false)

	tests := []struct {
		severity       string
		shouldHaveANSI bool
	}{
		{"CRITICAL", true},
		{"HIGH", true},
		{"MEDIUM", true},
		{"LOW", false},
		{"UNKNOWN", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := colorSeverity(tt.severity)
			hasANSI := strings.Contains(got, "\033[")

			if hasANSI != tt.shouldHaveANSI {
				if tt.shouldHaveANSI {
					t.Errorf("colorSeverity(%q) should contain ANSI codes when colors enabled, got %q", tt.severity, got)
				} else {
					t.Errorf("colorSeverity(%q) should not contain ANSI codes, got %q", tt.severity, got)
				}
			}

			// Should still contain the severity text
			if !strings.Contains(got, tt.severity) {
				t.Errorf("colorSeverity(%q) should contain severity text, got %q", tt.severity, got)
			}
		})
	}
}

func TestMain(m *testing.M) {
	// Disable colors for all tests to prevent ANSI codes from interfering
	ui.SetEnabled(false)
	os.Exit(m.Run())
}

func TestRenderDecision_ExampleBlockedDecision_Korean(t *testing.T) {
	tr, err := i18n.New("ko")
	if err != nil {
		t.Fatalf("i18n.New(ko) error = %v", err)
	}

	d := decision.ExampleBlockedDecision()
	out := RenderDecision(d, tr)

	// Summary should be Korean (not English)
	if !strings.Contains(out, "심각한 보안 위반으로 인해 배포가 차단되었습니다") {
		t.Errorf("ExampleBlockedDecision summary not Korean.\nGot:\n%s", out)
	}

	// Violation messages should be Korean with interpolated values
	// Use collapseWhitespace to handle line wrapping
	collapsed := collapseWhitespace(out)
	if !strings.Contains(collapsed, "특권(privileged) 컨테이너는 허용되지 않습니다") {
		t.Errorf("Privileged violation message not Korean.\nGot:\n%s", out)
	}
	if !strings.Contains(collapsed, "'nginx'") {
		t.Errorf("Privileged violation message missing container name.\nGot:\n%s", out)
	}
	if !strings.Contains(collapsed, "이미지 'nginx:latest'") {
		t.Errorf("Image violation message not Korean.\nGot:\n%s", out)
	}

	// Next action titles should be Korean
	if !strings.Contains(out, "배포 매니페스트 업데이트") {
		t.Errorf("Next action title not Korean.\nGot:\n%s", out)
	}
	if !strings.Contains(out, "로컬에서 이미지 스캔") {
		t.Errorf("Scan action title not Korean.\nGot:\n%s", out)
	}
}
