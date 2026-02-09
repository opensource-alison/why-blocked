package output

import (
	"encoding/json"

	"github.com/alisonui/why-blocked/internal/decision"
)

// DecisionEnvelope is the top-level JSON output for a SecurityDecision.
type DecisionEnvelope struct {
	SchemaVersion string       `json:"schemaVersion"`
	Decision      decisionView `json:"decision"`
}

type decisionView struct {
	ID          string            `json:"id"`
	Timestamp   string            `json:"timestamp"`
	Version     string            `json:"version"`
	Status      string            `json:"status"`
	Summary     string            `json:"summary"`
	Resource    resourceView      `json:"resource"`
	Violations  []violationView   `json:"violations"`
	NextActions []actionView      `json:"nextActions"`
	Metadata    map[string]string `json:"metadata"`
}

type resourceView struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type violationView struct {
	PolicyID   string         `json:"policyId"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`
	Message    string         `json:"message"`
	Evidence   []evidenceView `json:"evidence"`
	Fix        []actionView   `json:"fix"`
	References []string       `json:"references"`
}

type evidenceView struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	Raw     any    `json:"raw"`
}

type actionView struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Patch  any    `json:"patch,omitempty"`
}

// RenderDecisionJSON returns pretty-printed JSON for a SecurityDecision.
func RenderDecisionJSON(d decision.SecurityDecision) ([]byte, error) {
	env := DecisionEnvelope{
		SchemaVersion: "v1",
		Decision:      toDecisionView(d),
	}
	return json.MarshalIndent(env, "", "  ")
}

func toDecisionView(d decision.SecurityDecision) decisionView {
	violations := make([]violationView, len(d.Violations))
	for i, v := range d.Violations {
		violations[i] = toViolationView(v)
	}

	nextActions := make([]actionView, len(d.NextActions))
	for i, a := range d.NextActions {
		nextActions[i] = toActionView(a)
	}

	meta := d.Metadata
	if meta == nil {
		meta = map[string]string{}
	}

	return decisionView{
		ID:        d.ID,
		Timestamp: d.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Version:   d.Version,
		Status:    string(d.Status),
		Summary:   d.Summary,
		Resource: resourceView{
			Kind:      d.Resource.Kind,
			Name:      d.Resource.Name,
			Namespace: d.Resource.Namespace,
		},
		Violations:  violations,
		NextActions: nextActions,
		Metadata:    meta,
	}
}

func toViolationView(v decision.Violation) violationView {
	evidence := make([]evidenceView, len(v.Evidence))
	for i, e := range v.Evidence {
		raw := any(e.Raw)
		if e.Raw == nil {
			raw = map[string]any{}
		}
		evidence[i] = evidenceView{
			Type:    string(e.Type),
			Subject: e.Subject,
			Detail:  e.Detail,
			Raw:     raw,
		}
	}

	fix := make([]actionView, len(v.Fix))
	for i, f := range v.Fix {
		fix[i] = toActionView(f)
	}

	refs := v.References
	if refs == nil {
		refs = []string{}
	}

	return violationView{
		PolicyID:   v.PolicyID,
		Title:      v.Title,
		Severity:   string(v.Severity),
		Message:    v.Message,
		Evidence:   evidence,
		Fix:        fix,
		References: refs,
	}
}

func toActionView(a decision.Action) actionView {
	av := actionView{
		Title:  a.Title,
		Detail: a.Detail,
	}
	if a.Patch.Format != "" || a.Patch.Content != "" {
		av.Patch = a.Patch
	}
	return av
}
