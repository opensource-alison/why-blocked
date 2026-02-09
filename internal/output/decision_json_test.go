package output

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/alisonui/why-blocked/internal/decision"
)

func TestRenderDecisionJSON_ValidJSON(t *testing.T) {
	d := decision.ExampleBlockedDecision()
	data, err := RenderDecisionJSON(d)
	if err != nil {
		t.Fatalf("RenderDecisionJSON() error = %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("RenderDecisionJSON() returned invalid JSON")
	}
}

func TestRenderDecisionJSON_SchemaVersion(t *testing.T) {
	d := decision.ExampleBlockedDecision()
	data, err := RenderDecisionJSON(d)
	if err != nil {
		t.Fatalf("RenderDecisionJSON() error = %v", err)
	}

	var env DecisionEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if env.SchemaVersion != "v1" {
		t.Errorf("schemaVersion = %q, want %q", env.SchemaVersion, "v1")
	}
}

func TestRenderDecisionJSON_DecisionID(t *testing.T) {
	d := decision.ExampleBlockedDecision()
	data, err := RenderDecisionJSON(d)
	if err != nil {
		t.Fatalf("RenderDecisionJSON() error = %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	var dec map[string]json.RawMessage
	if err := json.Unmarshal(raw["decision"], &dec); err != nil {
		t.Fatalf("Unmarshal decision error = %v", err)
	}

	var id string
	if err := json.Unmarshal(dec["id"], &id); err != nil {
		t.Fatalf("Unmarshal id error = %v", err)
	}
	if id != "dec-7721" {
		t.Errorf("decision.id = %q, want %q", id, "dec-7721")
	}
}

func TestRenderDecisionJSON_EmptyArrays(t *testing.T) {
	d := decision.SecurityDecision{
		ID:        "test-empty",
		Timestamp: time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusAllowed,
		Summary:   "Allowed",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "safe-app",
			Namespace: "default",
		},
	}

	data, err := RenderDecisionJSON(d)
	if err != nil {
		t.Fatalf("RenderDecisionJSON() error = %v", err)
	}

	var env DecisionEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	// violations and nextActions must be arrays, not null
	if env.Decision.Violations == nil {
		t.Error("decision.violations is nil, want empty array")
	}
	if env.Decision.NextActions == nil {
		t.Error("decision.nextActions is nil, want empty array")
	}
	if env.Decision.Metadata == nil {
		t.Error("decision.metadata is nil, want empty object")
	}
}

func TestRenderDecisionJSON_ViolationEvidenceArrays(t *testing.T) {
	d := decision.SecurityDecision{
		ID:        "test-evidence",
		Timestamp: time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC),
		Version:   "v1alpha1",
		Status:    decision.StatusBlocked,
		Summary:   "Blocked",
		Resource: decision.ResourceRef{
			Kind:      "Deployment",
			Name:      "test",
			Namespace: "default",
		},
		Violations: []decision.Violation{
			{
				PolicyID: "POL-001",
				Title:    "No evidence violation",
				Severity: decision.SeverityLow,
				Message:  "Test",
			},
		},
	}

	data, err := RenderDecisionJSON(d)
	if err != nil {
		t.Fatalf("RenderDecisionJSON() error = %v", err)
	}

	var env DecisionEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	v := env.Decision.Violations[0]
	if v.Evidence == nil {
		t.Error("violation.evidence is nil, want empty array")
	}
	if v.Fix == nil {
		t.Error("violation.fix is nil, want empty array")
	}
	if v.References == nil {
		t.Error("violation.references is nil, want empty array")
	}
}

func TestRenderDecisionJSON_FullDecisionShape(t *testing.T) {
	d := decision.ExampleBlockedDecision()
	data, err := RenderDecisionJSON(d)
	if err != nil {
		t.Fatalf("RenderDecisionJSON() error = %v", err)
	}

	var env DecisionEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	dec := env.Decision
	if dec.Status != "BLOCKED" {
		t.Errorf("status = %q, want %q", dec.Status, "BLOCKED")
	}
	if dec.Resource.Kind != "Deployment" {
		t.Errorf("resource.kind = %q, want %q", dec.Resource.Kind, "Deployment")
	}
	if len(dec.Violations) != 2 {
		t.Fatalf("len(violations) = %d, want 2", len(dec.Violations))
	}
	if len(dec.Violations[0].Evidence) != 1 {
		t.Errorf("violations[0].evidence length = %d, want 1", len(dec.Violations[0].Evidence))
	}
	if len(dec.Violations[0].Fix) != 1 {
		t.Errorf("violations[0].fix length = %d, want 1", len(dec.Violations[0].Fix))
	}
	if len(dec.NextActions) != 2 {
		t.Errorf("len(nextActions) = %d, want 2", len(dec.NextActions))
	}
}
