package detect

import (
	"strings"
	"testing"
)

func TestDetectBlockSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		engine     string
		confidence string
		policyName string
		ruleName   string
	}{
		{
			name:       "psa",
			input:      `Error from server (Forbidden): error when creating "pod.yaml": pods "test-pod" is forbidden: violates PodSecurity "restricted:latest": privileged (container "web" must not set securityContext.privileged=true)`,
			engine:     "PSA",
			confidence: "high",
			policyName: "restricted",
		},
		{
			name:       "kyverno",
			input:      "Error from server: error when creating \"pod.yaml\": admission webhook \"validate.kyverno.svc-fail\" denied the request: \n\nresource Pod/default/test-pod was blocked due to the following policies \n\ndisallow-privileged-containers:\n  validate-privileged:\n    'validation error: Privileged mode is disallowed.'",
			engine:     "Kyverno",
			confidence: "high",
			policyName: "disallow-privileged-containers",
			ruleName:   "validate-privileged",
		},
		{
			name:       "gatekeeper",
			input:      `Error from server (Forbidden): error when creating "pod.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [denied by k8spsprivilegedcontainer] Privileged container is not allowed: web`,
			engine:     "Gatekeeper",
			confidence: "high",
			policyName: "k8spsprivilegedcontainer",
		},
		{
			name:       "rbac",
			input:      `Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:my-sa" cannot create resource "pods" in API group "" in the namespace "production"`,
			engine:     "RBAC",
			confidence: "high",
			policyName: `create resource "pods"`,
		},
		{
			name:       "generic webhook",
			input:      `Error from server: error when creating "pod.yaml": admission webhook "my-company-webhook.example.com" denied the request: container image must be from approved registry`,
			engine:     "Webhook",
			confidence: "medium",
			policyName: "my-company-webhook.example.com",
		},
		{
			name:       "unknown",
			input:      `Error from server (InternalError): Internal error occurred: failed calling webhook`,
			engine:     "Unknown",
			confidence: "low",
		},
		{
			name:       "empty string",
			input:      "",
			engine:     "Unknown",
			confidence: "low",
		},
		{
			name:       "specific match wins over generic webhook",
			input:      `Error from server: admission webhook "validate.kyverno.svc-fail" denied the request: policy disallow-privileged rule validate-privileged failed with validation error`,
			engine:     "Kyverno",
			confidence: "high",
			policyName: "disallow-privileged",
			ruleName:   "validate-privileged",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := DetectBlockSource(tt.input)
			if result == nil {
				t.Fatal("DetectBlockSource returned nil")
			}

			if result.Engine != tt.engine {
				t.Fatalf("Engine = %q, want %q", result.Engine, tt.engine)
			}
			if result.Confidence != tt.confidence {
				t.Fatalf("Confidence = %q, want %q", result.Confidence, tt.confidence)
			}
			if result.PolicyName != tt.policyName {
				t.Fatalf("PolicyName = %q, want %q", result.PolicyName, tt.policyName)
			}
			if result.RuleName != tt.ruleName {
				t.Fatalf("RuleName = %q, want %q", result.RuleName, tt.ruleName)
			}
			if len(result.Hints) == 0 {
				t.Fatal("Hints should not be empty")
			}
			if result.RawMessage != strings.TrimSpace(truncate(tt.input, 500)) {
				t.Fatalf("RawMessage = %q, want %q", result.RawMessage, strings.TrimSpace(truncate(tt.input, 500)))
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("a", 600)
	got := truncate(input, 500)
	if len(got) != 500 {
		t.Fatalf("truncate length = %d, want 500", len(got))
	}
}
