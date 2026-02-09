package decision

import (
	"encoding/json"
	"testing"
)

func TestExampleBlockedDecision(t *testing.T) {
	d := ExampleBlockedDecision()

	// Verify basic structure
	if d.ID == "" {
		t.Error("ExampleBlockedDecision() ID is empty")
	}
	if d.Status != StatusBlocked {
		t.Errorf("ExampleBlockedDecision() Status = %v, want %v", d.Status, StatusBlocked)
	}
	if d.Version != "v1alpha1" {
		t.Errorf("ExampleBlockedDecision() Version = %v, want v1alpha1", d.Version)
	}

	// Verify resource
	if d.Resource.Kind != "Deployment" {
		t.Errorf("ExampleBlockedDecision() Resource.Kind = %v, want Deployment", d.Resource.Kind)
	}
	if d.Resource.Namespace != "production" {
		t.Errorf("ExampleBlockedDecision() Resource.Namespace = %v, want production", d.Resource.Namespace)
	}

	// Verify timestamp is reasonable
	if d.Timestamp.IsZero() {
		t.Error("ExampleBlockedDecision() Timestamp is zero")
	}

	// Verify violations exist
	if len(d.Violations) == 0 {
		t.Fatal("ExampleBlockedDecision() has no violations")
	}

	// Test rule evaluation: privileged=true => CRITICAL
	foundPrivileged := false
	for _, v := range d.Violations {
		if v.PolicyID == "POL-SEC-001" {
			foundPrivileged = true
			if v.Title != "Privileged Container" {
				t.Errorf("Privileged violation Title = %v, want 'Privileged Container'", v.Title)
			}
			if v.Severity != SeverityCritical {
				t.Errorf("Privileged violation Severity = %v, want %v", v.Severity, SeverityCritical)
			}
			// Verify evidence mentions privileged
			if len(v.Evidence) == 0 {
				t.Error("Privileged violation has no evidence")
			} else {
				found := false
				for _, e := range v.Evidence {
					if e.Type == EvidenceK8sField && e.Subject == "spec.template.spec.containers[0].securityContext.privileged" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Privileged violation evidence does not mention securityContext.privileged field")
				}
			}
			// Verify fix suggestions exist
			if len(v.Fix) == 0 {
				t.Error("Privileged violation has no fix suggestions")
			}
		}
	}
	if !foundPrivileged {
		t.Error("ExampleBlockedDecision() missing privileged container violation (POL-SEC-001)")
	}

	// Test rule evaluation: nginx:latest => HIGH
	foundImageIssue := false
	for _, v := range d.Violations {
		if v.PolicyID == "POL-SEC-005" {
			foundImageIssue = true
			if v.Title != "Insecure Image Usage" {
				t.Errorf("Image violation Title = %v, want 'Insecure Image Usage'", v.Title)
			}
			if v.Severity != SeverityHigh {
				t.Errorf("Image violation Severity = %v, want %v", v.Severity, SeverityHigh)
			}
			// Verify evidence mentions nginx:latest
			if len(v.Evidence) == 0 {
				t.Error("Image violation has no evidence")
			} else {
				found := false
				for _, e := range v.Evidence {
					if e.Type == EvidenceImageScan && e.Subject == "nginx:latest" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Image violation evidence does not mention nginx:latest")
				}
			}
		}
	}
	if !foundImageIssue {
		t.Error("ExampleBlockedDecision() missing image issue violation (POL-SEC-005)")
	}

	// Verify next actions exist
	if len(d.NextActions) == 0 {
		t.Error("ExampleBlockedDecision() has no next actions")
	}

	// Verify metadata exists
	if len(d.Metadata) == 0 {
		t.Error("ExampleBlockedDecision() has no metadata")
	}

	// Verify the decision is valid
	if err := d.Validate(); err != nil {
		t.Errorf("ExampleBlockedDecision() is not valid: %v", err)
	}
}

func TestExampleBlockedDecision_HasI18nKeys(t *testing.T) {
	d := ExampleBlockedDecision()

	if d.SummaryKey == "" {
		t.Error("ExampleBlockedDecision() should have SummaryKey")
	}

	for i, v := range d.Violations {
		if v.TitleKey == "" {
			t.Errorf("Violation[%d] should have TitleKey", i)
		}
		if v.MessageKey == "" {
			t.Errorf("Violation[%d] should have MessageKey", i)
		}
	}

	for i, a := range d.NextActions {
		if a.TitleKey == "" {
			t.Errorf("NextAction[%d] should have TitleKey", i)
		}
		if a.DetailKey == "" {
			t.Errorf("NextAction[%d] should have DetailKey", i)
		}
	}
}

func TestExampleBlockedDecision_JSONCompat(t *testing.T) {
	d := ExampleBlockedDecision()

	// Marshal and unmarshal round-trip
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}

	var d2 SecurityDecision
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	// Key fields survive round-trip
	if d2.SummaryKey != d.SummaryKey {
		t.Errorf("SummaryKey mismatch: %q != %q", d2.SummaryKey, d.SummaryKey)
	}
	if d2.Violations[0].MessageKey != d.Violations[0].MessageKey {
		t.Errorf("Violations[0].MessageKey mismatch")
	}
	if d2.Violations[0].MessageArgs["container"] != "nginx" {
		t.Errorf("Violations[0].MessageArgs[container] = %q, want nginx", d2.Violations[0].MessageArgs["container"])
	}

	// Old string fields also survive
	if d2.Summary != d.Summary {
		t.Errorf("Summary mismatch: %q != %q", d2.Summary, d.Summary)
	}
	if d2.Violations[0].Title != d.Violations[0].Title {
		t.Errorf("Violations[0].Title mismatch")
	}
}

func TestOldJSON_WithoutKeys_Unmarshal(t *testing.T) {
	// Simulate a JSON from before keys were added
	oldJSON := `{
		"id": "old-1",
		"timestamp": "2026-02-05T16:00:00Z",
		"resource": {"kind": "Deployment", "name": "old", "namespace": "default"},
		"status": "BLOCKED",
		"summary": "Old decision",
		"violations": [{
			"policyId": "POL-001",
			"title": "Old title",
			"severity": "HIGH",
			"message": "Old message"
		}],
		"version": "v1alpha1"
	}`

	var d SecurityDecision
	if err := json.Unmarshal([]byte(oldJSON), &d); err != nil {
		t.Fatalf("json.Unmarshal old JSON error = %v", err)
	}

	// Key fields should be zero-valued
	if d.SummaryKey != "" {
		t.Errorf("SummaryKey should be empty for old JSON, got %q", d.SummaryKey)
	}
	if d.Violations[0].TitleKey != "" {
		t.Errorf("TitleKey should be empty for old JSON, got %q", d.Violations[0].TitleKey)
	}
	if d.Violations[0].MessageKey != "" {
		t.Errorf("MessageKey should be empty for old JSON, got %q", d.Violations[0].MessageKey)
	}

	// Old fields should parse correctly
	if d.Summary != "Old decision" {
		t.Errorf("Summary = %q, want %q", d.Summary, "Old decision")
	}
	if d.Violations[0].Title != "Old title" {
		t.Errorf("Violations[0].Title = %q, want %q", d.Violations[0].Title, "Old title")
	}
}

func TestExampleBlockedDecision_Deterministic(t *testing.T) {
	// Verify that calling ExampleBlockedDecision multiple times returns consistent structure
	d1 := ExampleBlockedDecision()
	d2 := ExampleBlockedDecision()

	if d1.ID != d2.ID {
		t.Errorf("ExampleBlockedDecision() ID not deterministic: %v != %v", d1.ID, d2.ID)
	}
	if d1.Status != d2.Status {
		t.Errorf("ExampleBlockedDecision() Status not deterministic")
	}
	if len(d1.Violations) != len(d2.Violations) {
		t.Errorf("ExampleBlockedDecision() Violations count not deterministic: %d != %d", len(d1.Violations), len(d2.Violations))
	}
}
