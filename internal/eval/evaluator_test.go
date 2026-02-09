package eval

import (
	"testing"
	"time"

	"github.com/alisonui/why-blocked/internal/decision"
)

// Fixed timestamp for deterministic tests
var testTimestamp = time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)

func TestEvaluator_PrivilegedContainer(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "nginx-deployment",
			"namespace": "production",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "nginx",
							"image": "nginx:1.21.0",
							"securityContext": map[string]interface{}{
								"privileged": true,
							},
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-001")

	// Assertions
	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	if len(result.Violations) == 0 {
		t.Fatal("Expected at least 1 violation")
	}

	// Check for CRITICAL violation
	hasCritical := false
	hasPrivilegedViolation := false
	var privilegedViolation *decision.Violation

	for i := range result.Violations {
		v := &result.Violations[i]
		if v.Severity == decision.SeverityCritical {
			hasCritical = true
		}
		if v.PolicyID == "POL-SEC-001" {
			hasPrivilegedViolation = true
			privilegedViolation = v
		}
	}

	if !hasCritical {
		t.Error("Expected at least 1 CRITICAL violation")
	}

	if !hasPrivilegedViolation {
		t.Error("Expected privileged container violation")
	}

	// Check evidence includes field path
	if privilegedViolation != nil {
		if len(privilegedViolation.Evidence) == 0 {
			t.Error("Expected evidence for privileged violation")
		} else {
			evidence := privilegedViolation.Evidence[0]
			if evidence.Type != decision.EvidenceK8sField {
				t.Errorf("Expected evidence type K8S_FIELD, got %s", evidence.Type)
			}
			if evidence.Subject != "spec.template.spec.containers[0].securityContext.privileged" {
				t.Errorf("Expected field path in evidence subject, got %s", evidence.Subject)
			}
		}

		// Check for fix suggestions
		if len(privilegedViolation.Fix) == 0 {
			t.Error("Expected fix suggestions for privileged violation")
		}
	}

	// Verify resource reference
	if result.Resource.Kind != "Deployment" {
		t.Errorf("Expected Kind=Deployment, got %s", result.Resource.Kind)
	}
	if result.Resource.Name != "nginx-deployment" {
		t.Errorf("Expected Name=nginx-deployment, got %s", result.Resource.Name)
	}
	if result.Resource.Namespace != "production" {
		t.Errorf("Expected Namespace=production, got %s", result.Resource.Namespace)
	}
}

func TestEvaluator_HostPathVolume(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "app-deployment",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "app",
							"image": "myapp:1.0.0",
						},
					},
					"volumes": []interface{}{
						map[string]interface{}{
							"name": "host-volume",
							"hostPath": map[string]interface{}{
								"path": "/var/run/docker.sock",
							},
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-002")

	// Assertions
	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	if len(result.Violations) == 0 {
		t.Fatal("Expected at least 1 violation")
	}

	// Check for HIGH severity violation
	hasHigh := false
	hasHostPathViolation := false
	var hostPathViolation *decision.Violation

	for i := range result.Violations {
		v := &result.Violations[i]
		if v.Severity == decision.SeverityHigh {
			hasHigh = true
		}
		if v.PolicyID == "POL-SEC-002" {
			hasHostPathViolation = true
			hostPathViolation = v
		}
	}

	if !hasHigh {
		t.Error("Expected at least 1 HIGH severity violation")
	}

	if !hasHostPathViolation {
		t.Error("Expected hostPath violation")
	}

	// Check evidence
	if hostPathViolation != nil {
		if len(hostPathViolation.Evidence) == 0 {
			t.Error("Expected evidence for hostPath violation")
		} else {
			evidence := hostPathViolation.Evidence[0]
			if evidence.Type != decision.EvidenceK8sField {
				t.Errorf("Expected evidence type K8S_FIELD, got %s", evidence.Type)
			}
		}
	}
}

func TestEvaluator_RunAsNonRootMissing(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "insecure-deployment",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "app",
							"image": "myapp:2.0.0",
							// No securityContext with runAsNonRoot
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-003")

	// Assertions
	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	if len(result.Violations) == 0 {
		t.Fatal("Expected at least 1 violation")
	}

	// Check for runAsNonRoot violation
	hasRunAsNonRootViolation := false
	for i := range result.Violations {
		v := &result.Violations[i]
		if v.PolicyID == "POL-SEC-003" {
			hasRunAsNonRootViolation = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for runAsNonRoot violation, got %s", v.Severity)
			}
		}
	}

	if !hasRunAsNonRootViolation {
		t.Error("Expected runAsNonRoot violation")
	}
}

func TestEvaluator_LatestImageTag(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "latest-tag-deployment",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "nginx",
							"image": "nginx:latest",
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-004")

	// Assertions
	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	if len(result.Violations) == 0 {
		t.Fatal("Expected at least 1 violation")
	}

	// Check for latest tag violation
	hasLatestTagViolation := false
	for i := range result.Violations {
		v := &result.Violations[i]
		if v.PolicyID == "POL-SEC-004" {
			hasLatestTagViolation = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for latest tag violation, got %s", v.Severity)
			}

			// Check evidence contains the image reference
			if len(v.Evidence) == 0 {
				t.Error("Expected evidence for latest tag violation")
			} else {
				evidence := v.Evidence[0]
				if evidence.Detail != "nginx:latest" {
					t.Errorf("Expected evidence detail to contain 'nginx:latest', got %s", evidence.Detail)
				}
			}
		}
	}

	if !hasLatestTagViolation {
		t.Error("Expected latest tag violation")
	}
}

func TestEvaluator_SafeBaseline(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "secure-deployment",
			"namespace": "production",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"securityContext": map[string]interface{}{
						"runAsNonRoot": true,
					},
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "app",
							"image": "myapp:1.2.3",
							"securityContext": map[string]interface{}{
								"privileged":   false,
								"runAsNonRoot": true,
							},
						},
					},
					"volumes": []interface{}{
						map[string]interface{}{
							"name": "config-volume",
							"configMap": map[string]interface{}{
								"name": "app-config",
							},
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-005")

	// Assertions
	if result.Status != decision.StatusAllowed {
		t.Errorf("Expected status ALLOWED, got %s", result.Status)
	}

	if len(result.Violations) != 0 {
		t.Errorf("Expected no violations for safe baseline, got %d violations", len(result.Violations))
		for _, v := range result.Violations {
			t.Logf("  Unexpected violation: %s - %s", v.PolicyID, v.Title)
		}
	}

	// Verify decision metadata
	if result.ID != "test-005" {
		t.Errorf("Expected ID=test-005, got %s", result.ID)
	}

	if result.Version != "v1alpha1" {
		t.Errorf("Expected Version=v1alpha1, got %s", result.Version)
	}

	if !result.Timestamp.Equal(testTimestamp) {
		t.Errorf("Expected timestamp %v, got %v", testTimestamp, result.Timestamp)
	}

	// Verify summary indicates success
	if result.Summary != "Resource meets security requirements" {
		t.Errorf("Expected success summary, got: %s", result.Summary)
	}

	// Verify no next actions for allowed resources
	if len(result.NextActions) != 0 {
		t.Errorf("Expected no next actions for allowed resource, got %d", len(result.NextActions))
	}
}

// TestEvaluator_PodDirectly tests evaluation of a Pod resource (not Deployment)
func TestEvaluator_PodDirectly(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "nginx",
					"image": "nginx:latest",
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-006")

	// Should still detect violations in Pod resources
	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED for Pod with latest tag, got %s", result.Status)
	}

	if result.Resource.Kind != "Pod" {
		t.Errorf("Expected Kind=Pod, got %s", result.Resource.Kind)
	}
}

// TestEvaluator_MultipleViolations tests a spec with multiple violations
func TestEvaluator_MultipleViolations(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "very-insecure",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "app",
							"image": "app:latest",
							"securityContext": map[string]interface{}{
								"privileged": true,
							},
						},
					},
					"volumes": []interface{}{
						map[string]interface{}{
							"name": "host-vol",
							"hostPath": map[string]interface{}{
								"path": "/",
							},
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-007")

	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	// Should have multiple violations
	if len(result.Violations) < 2 {
		t.Errorf("Expected at least 2 violations (privileged + latest/hostPath), got %d", len(result.Violations))
	}

	// Count violation types
	violationTypes := make(map[string]bool)
	for _, v := range result.Violations {
		violationTypes[v.PolicyID] = true
	}

	// Should have at least privileged violation
	if !violationTypes["POL-SEC-001"] {
		t.Error("Expected privileged container violation")
	}
}
