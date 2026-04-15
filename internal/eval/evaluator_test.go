package eval

import (
	"strings"
	"testing"
	"time"

	"github.com/alisonui/why-blocked/internal/decision"
)

// Fixed timestamp for deterministic tests
var testTimestamp = time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)

func findViolationByID(violations []decision.Violation, policyID string) *decision.Violation {
	for i := range violations {
		if violations[i].PolicyID == policyID {
			return &violations[i]
		}
	}
	return nil
}

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

		// Check standards references
		if len(privilegedViolation.Standards) == 0 {
			t.Error("Expected standards references for privileged violation")
		} else {
			hasCI := false
			hasPSA := false
			for _, s := range privilegedViolation.Standards {
				if s.ID == "CIS 5.2.1" {
					hasCI = true
				}
				if s.ID == "PSA restricted" {
					hasPSA = true
				}
			}
			if !hasCI {
				t.Error("Expected CIS 5.2.1 standard for privileged violation")
			}
			if !hasPSA {
				t.Error("Expected PSA restricted standard for privileged violation")
			}
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

		// Check standards references
		if len(hostPathViolation.Standards) == 0 {
			t.Error("Expected standards references for hostPath violation")
		} else {
			hasCI := false
			hasPSA := false
			for _, s := range hostPathViolation.Standards {
				if s.ID == "CIS 5.2.8" {
					hasCI = true
				}
				if s.ID == "PSA baseline" {
					hasPSA = true
				}
			}
			if !hasCI {
				t.Error("Expected CIS 5.2.8 standard for hostPath violation")
			}
			if !hasPSA {
				t.Error("Expected PSA baseline standard for hostPath violation")
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
	var runAsNonRootViolation *decision.Violation
	for i := range result.Violations {
		v := &result.Violations[i]
		if v.PolicyID == "POL-SEC-003" {
			hasRunAsNonRootViolation = true
			runAsNonRootViolation = v
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for runAsNonRoot violation, got %s", v.Severity)
			}
		}
	}

	if !hasRunAsNonRootViolation {
		t.Error("Expected runAsNonRoot violation")
	}

	// Check standards references
	if runAsNonRootViolation != nil {
		if len(runAsNonRootViolation.Standards) == 0 {
			t.Error("Expected standards references for runAsNonRoot violation")
		} else {
			hasCI := false
			hasPSA := false
			for _, s := range runAsNonRootViolation.Standards {
				if s.ID == "CIS 5.2.6" {
					hasCI = true
				}
				if s.ID == "PSA restricted" {
					hasPSA = true
				}
			}
			if !hasCI {
				t.Error("Expected CIS 5.2.6 standard for runAsNonRoot violation")
			}
			if !hasPSA {
				t.Error("Expected PSA restricted standard for runAsNonRoot violation")
			}
		}
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
	var latestTagViolation *decision.Violation
	for i := range result.Violations {
		v := &result.Violations[i]
		if v.PolicyID == "POL-SEC-004" {
			hasLatestTagViolation = true
			latestTagViolation = v
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

	// Check standards references
	if latestTagViolation != nil {
		if len(latestTagViolation.Standards) == 0 {
			t.Error("Expected standards references for latest tag violation")
		} else {
			hasCI := false
			for _, s := range latestTagViolation.Standards {
				if s.ID == "CIS 5.5.1" {
					hasCI = true
				}
			}
			if !hasCI {
				t.Error("Expected CIS 5.5.1 standard for latest tag violation")
			}
		}
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
								"privileged":               false,
								"runAsNonRoot":             true,
								"allowPrivilegeEscalation": false,
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

	if len(result.Violations) != 1 {
		t.Errorf("Expected 1 advisory for safe baseline, got %d violations", len(result.Violations))
		for _, v := range result.Violations {
			t.Logf("  Unexpected violation: %s - %s", v.PolicyID, v.Title)
		}
	}

	advisory := findViolationByID(result.Violations, "ADV-NET-001")
	if advisory == nil {
		t.Fatal("Expected ADV-NET-001 advisory for safe baseline")
	}
	if advisory.Severity != decision.SeverityInfo {
		t.Fatalf("Expected ADV-NET-001 severity INFO, got %s", advisory.Severity)
	}
	if len(advisory.Standards) == 0 || advisory.Standards[0].ID != "CIS 5.3.2" {
		t.Fatalf("Expected ADV-NET-001 to include CIS 5.3.2 standard, got %+v", advisory.Standards)
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
	if result.Summary != "Resource meets security requirements with 1 advisory" {
		t.Errorf("Expected success summary, got: %s", result.Summary)
	}

	// Verify no next actions for allowed resources
	if len(result.NextActions) != 0 {
		t.Errorf("Expected no next actions for allowed resource, got %d", len(result.NextActions))
	}
}

func TestEvaluator_InfoAdvisoryDoesNotBlock(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-pod", "namespace": "production"},
		"spec": map[string]interface{}{
			"securityContext": map[string]interface{}{
				"runAsNonRoot": true,
			},
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.2.3",
					"securityContext": map[string]interface{}{
						"runAsNonRoot":             true,
						"allowPrivilegeEscalation": false,
						"privileged":               false,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-info-001")

	if result.Status != decision.StatusAllowed {
		t.Fatalf("Expected ALLOWED status for INFO-only result, got %s", result.Status)
	}
	if findViolationByID(result.Violations, "ADV-NET-001") == nil {
		t.Fatal("Expected ADV-NET-001 advisory for Pod resource")
	}
	if len(result.NextActions) != 0 {
		t.Fatalf("Expected no next actions for INFO-only result, got %d", len(result.NextActions))
	}
}

func TestEvaluator_BlockingViolationAndInfoAdvisory(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "priv-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-info-002")

	if result.Status != decision.StatusBlocked {
		t.Fatalf("Expected BLOCKED status for privileged Pod, got %s", result.Status)
	}
	if findViolationByID(result.Violations, "POL-SEC-001") == nil {
		t.Fatal("Expected POL-SEC-001 violation")
	}
	if findViolationByID(result.Violations, "ADV-NET-001") == nil {
		t.Fatal("Expected ADV-NET-001 advisory alongside blocking violation")
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

// --- POL-SEC-005: hostPID ---

func TestEvaluator_HostPID_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "hostpid-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"hostPID": true,
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-hostpid-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-005" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for hostPID violation, got %s", v.Severity)
			}
			if len(v.Standards) == 0 {
				t.Error("Expected standards for hostPID violation")
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-005 (hostPID) violation")
	}
}

func TestEvaluator_HostPID_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			// hostPID not set
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
			"securityContext": map[string]interface{}{"runAsNonRoot": true},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-hostpid-002")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-005" {
			t.Errorf("Expected no POL-SEC-005 violation when hostPID is not set")
		}
	}
}

// --- POL-SEC-006: hostNetwork ---

func TestEvaluator_HostNetwork_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "hostnet-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"hostNetwork": true,
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-hostnet-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-006" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for hostNetwork violation, got %s", v.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-006 (hostNetwork) violation")
	}
}

func TestEvaluator_HostNetwork_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-hostnet-002")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-006" {
			t.Error("Expected no POL-SEC-006 violation when hostNetwork is not set")
		}
	}
}

// --- POL-SEC-007: hostIPC ---

func TestEvaluator_HostIPC_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "hostipc-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"hostIPC": true,
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-hostipc-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-007" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for hostIPC violation, got %s", v.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-007 (hostIPC) violation")
	}
}

func TestEvaluator_HostIPC_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-hostipc-002")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-007" {
			t.Error("Expected no POL-SEC-007 violation when hostIPC is not set")
		}
	}
}

// --- POL-SEC-008: dangerous capabilities ---

func TestEvaluator_DangerousCaps_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "caps-deployment", "namespace": "default"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "app",
							"image": "myapp:1.0.0",
							"securityContext": map[string]interface{}{
								"allowPrivilegeEscalation": false,
								"runAsNonRoot":             true,
								"capabilities": map[string]interface{}{
									"add": []interface{}{"SYS_ADMIN"},
								},
							},
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-caps-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-008" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for dangerous caps violation, got %s", v.Severity)
			}
			// Capability name must appear in evidence detail
			if len(v.Evidence) == 0 {
				t.Error("Expected evidence for dangerous caps violation")
			} else if v.Evidence[0].Detail != "Container adds dangerous capability: SYS_ADMIN" {
				t.Errorf("Expected evidence detail with cap name, got: %s", v.Evidence[0].Detail)
			}
			// MessageArgs should include cap
			if v.MessageArgs["cap"] != "SYS_ADMIN" {
				t.Errorf("Expected MessageArgs[cap]=SYS_ADMIN, got %s", v.MessageArgs["cap"])
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-008 (dangerous caps) violation for SYS_ADMIN")
	}
}

func TestEvaluator_DangerousCaps_AllDangerous(t *testing.T) {
	caps := []string{"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_RAWIO", "NET_RAW"}
	evaluator := New("v1alpha1")

	for _, cap := range caps {
		spec := map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]interface{}{"name": "caps-pod", "namespace": "default"},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":  "app",
						"image": "myapp:1.0.0",
						"securityContext": map[string]interface{}{
							"allowPrivilegeEscalation": false,
							"runAsNonRoot":             true,
							"capabilities": map[string]interface{}{
								"add": []interface{}{cap},
							},
						},
					},
				},
			},
		}
		result := evaluator.Evaluate(spec, testTimestamp, "test-caps-all")
		found := false
		for _, v := range result.Violations {
			if v.PolicyID == "POL-SEC-008" {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected POL-SEC-008 violation for capability %s", cap)
		}
	}
}

func TestEvaluator_DangerousCaps_SafeCap(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-caps-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
						"capabilities": map[string]interface{}{
							"add": []interface{}{"NET_BIND_SERVICE"}, // safe cap
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-caps-safe")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-008" {
			t.Error("Expected no POL-SEC-008 violation for NET_BIND_SERVICE (safe capability)")
		}
	}
}

// --- POL-SEC-009: allowPrivilegeEscalation ---

func TestEvaluator_AllowPrivilegeEscalation_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "ape-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"runAsNonRoot": true,
						// allowPrivilegeEscalation not set → violation
					},
				},
			},
			"securityContext": map[string]interface{}{"runAsNonRoot": true},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-ape-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-009" {
			found = true
			if v.Severity != decision.SeverityMedium {
				t.Errorf("Expected MEDIUM severity for allowPrivilegeEscalation violation, got %s", v.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-009 violation when allowPrivilegeEscalation is not set")
	}
}

func TestEvaluator_AllowPrivilegeEscalation_ExplicitTrue_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "ape-true-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"runAsNonRoot":             true,
						"allowPrivilegeEscalation": true, // explicitly true → violation
					},
				},
			},
			"securityContext": map[string]interface{}{"runAsNonRoot": true},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-ape-002")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-009" {
			found = true
		}
	}
	if !found {
		t.Error("Expected POL-SEC-009 violation when allowPrivilegeEscalation is explicitly true")
	}
}

func TestEvaluator_AllowPrivilegeEscalation_ExplicitFalse_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "safe-ape-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"runAsNonRoot":             true,
						"allowPrivilegeEscalation": false, // explicitly false → no violation
					},
				},
			},
			"securityContext": map[string]interface{}{"runAsNonRoot": true},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-ape-003")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-009" {
			t.Error("Expected no POL-SEC-009 violation when allowPrivilegeEscalation is explicitly false")
		}
	}
}

// --- POL-SEC-010: runAsRoot ---

func TestEvaluator_RunAsRoot_ContainerLevel(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "root-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"runAsUser":                float64(0), // UID 0 = root
						"allowPrivilegeEscalation": false,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-root-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-010" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for runAsRoot violation, got %s", v.Severity)
			}
			if len(v.Evidence) == 0 {
				t.Error("Expected evidence for runAsRoot violation")
			} else if v.Evidence[0].Detail != "runAsUser is explicitly set to 0 (root)" {
				t.Errorf("Unexpected evidence detail: %s", v.Evidence[0].Detail)
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-010 violation for container runAsUser: 0")
	}
}

func TestEvaluator_RunAsRoot_PodLevel(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "root-pod-level", "namespace": "default"},
		"spec": map[string]interface{}{
			"securityContext": map[string]interface{}{
				"runAsUser": float64(0), // pod-level UID 0
			},
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"allowPrivilegeEscalation": false,
						// no container-level runAsUser
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-root-002")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-010" {
			found = true
			if v.Evidence[0].Subject != "pod" {
				t.Errorf("Expected pod-level subject for pod-level runAsRoot, got %s", v.Evidence[0].Subject)
			}
		}
	}
	if !found {
		t.Error("Expected POL-SEC-010 violation for pod-level runAsUser: 0")
	}
}

func TestEvaluator_RunAsRoot_NonZeroUID_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "nonroot-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"runAsUser":                float64(1000), // non-root UID
						"allowPrivilegeEscalation": false,
						"runAsNonRoot":             true,
					},
				},
			},
			"securityContext": map[string]interface{}{"runAsNonRoot": true},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-root-003")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-010" {
			t.Error("Expected no POL-SEC-010 violation for non-zero UID")
		}
	}
}

// --- POL-RBAC-001: wildcard resources or verbs ---

func TestEvaluator_RBAC_WildcardResources_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "all-access"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"*"},
				"verbs":     []interface{}{"*"},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-001")

	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-001" {
			found = true
			if v.Severity != decision.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for wildcard violation, got %s", v.Severity)
			}
			if len(v.Standards) == 0 {
				t.Error("Expected standards for wildcard violation")
			} else if v.Standards[0].ID != "CIS 5.1.3" {
				t.Errorf("Expected CIS 5.1.3, got %s", v.Standards[0].ID)
			}
			if len(v.Evidence) == 0 {
				t.Error("Expected evidence for wildcard violation")
			} else if v.Evidence[0].Type != decision.EvidenceConfig {
				t.Errorf("Expected evidence type CONFIG, got %s", v.Evidence[0].Type)
			}
		}
	}
	if !found {
		t.Error("Expected POL-RBAC-001 (wildcard permissions) violation")
	}
}

func TestEvaluator_RBAC_WildcardVerbs_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": "verb-wildcard", "namespace": "default"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods"},
				"verbs":     []interface{}{"*"},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-002")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-001" {
			found = true
		}
	}
	if !found {
		t.Error("Expected POL-RBAC-001 violation for wildcard verbs")
	}
}

func TestEvaluator_RBAC_NoWildcard_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": "limited-role", "namespace": "default"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods"},
				"verbs":     []interface{}{"get", "list"},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-003")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-001" {
			t.Error("Expected no POL-RBAC-001 violation for explicit non-wildcard permissions")
		}
	}
}

// --- POL-RBAC-002: unrestricted secret access ---

func TestEvaluator_RBAC_SecretAccess_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": "secret-reader", "namespace": "default"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"secrets"},
				"verbs":     []interface{}{"get", "list"},
				// no resourceNames → unrestricted
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-004")

	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-002" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for secret access violation, got %s", v.Severity)
			}
			if len(v.Standards) == 0 {
				t.Error("Expected standards for secret access violation")
			} else if v.Standards[0].ID != "CIS 5.1.2" {
				t.Errorf("Expected CIS 5.1.2, got %s", v.Standards[0].ID)
			}
		}
	}
	if !found {
		t.Error("Expected POL-RBAC-002 (unrestricted secret access) violation")
	}
}

func TestEvaluator_RBAC_SecretAccess_WithResourceNames_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": "named-secret-reader", "namespace": "default"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups":     []interface{}{""},
				"resources":     []interface{}{"secrets"},
				"verbs":         []interface{}{"get", "list"},
				"resourceNames": []interface{}{"my-secret"}, // restricted → no violation
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-005")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-002" {
			t.Error("Expected no POL-RBAC-002 violation when resourceNames restricts secret access")
		}
	}
}

// --- POL-RBAC-003: pods/exec permission ---

func TestEvaluator_RBAC_PodExec_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "exec-allowed"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods/exec"},
				"verbs":     []interface{}{"create"},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-006")

	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-003" {
			found = true
			if v.Severity != decision.SeverityHigh {
				t.Errorf("Expected HIGH severity for pods/exec violation, got %s", v.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected POL-RBAC-003 (pods/exec) violation")
	}
}

func TestEvaluator_RBAC_PodGet_NoExecViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "pod-reader"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods"},
				"verbs":     []interface{}{"get", "list"},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-007")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-003" {
			t.Error("Expected no POL-RBAC-003 violation for pods get (no exec)")
		}
	}
}

// --- POL-RBAC-004: ClusterRoleBinding to cluster-admin ---

func TestEvaluator_RBAC_ClusterAdminBinding_Violation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": "admin-binding"},
		"roleRef": map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "cluster-admin",
		},
		"subjects": []interface{}{
			map[string]interface{}{
				"kind":      "ServiceAccount",
				"name":      "my-sa",
				"namespace": "default",
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-008")

	if result.Status != decision.StatusBlocked {
		t.Errorf("Expected status BLOCKED, got %s", result.Status)
	}

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-004" {
			found = true
			if v.Severity != decision.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for cluster-admin binding violation, got %s", v.Severity)
			}
			if len(v.Standards) == 0 {
				t.Error("Expected standards for cluster-admin binding violation")
			} else if v.Standards[0].ID != "CIS 5.1.1" {
				t.Errorf("Expected CIS 5.1.1, got %s", v.Standards[0].ID)
			}
			if len(v.Evidence) == 0 {
				t.Error("Expected evidence for cluster-admin binding violation")
			} else if v.Evidence[0].Subject != "my-sa" {
				t.Errorf("Expected evidence subject=my-sa, got %s", v.Evidence[0].Subject)
			}
		}
	}
	if !found {
		t.Error("Expected POL-RBAC-004 (cluster-admin binding) violation")
	}
}

func TestEvaluator_RBAC_CustomRoleBinding_NoViolation(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]interface{}{"name": "limited-binding"},
		"roleRef": map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "custom-reader", // not cluster-admin → no violation
		},
		"subjects": []interface{}{
			map[string]interface{}{
				"kind":      "ServiceAccount",
				"name":      "my-sa",
				"namespace": "default",
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-009")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-004" {
			t.Error("Expected no POL-RBAC-004 violation for non-cluster-admin binding")
		}
	}
}

// --- Cross-kind isolation ---

func TestEvaluator_PodSpec_DoesNotTriggerRBACRules(t *testing.T) {
	evaluator := New("v1alpha1")

	// A pod with privileged container should trigger POL-SEC-001 but NO RBAC rules
	spec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "priv-pod", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "app",
					"image": "myapp:1.0.0",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-010")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-001" || v.PolicyID == "POL-RBAC-002" ||
			v.PolicyID == "POL-RBAC-003" || v.PolicyID == "POL-RBAC-004" {
			t.Errorf("Expected no RBAC violations for Pod resource, got %s", v.PolicyID)
		}
	}
}

func TestEvaluator_Job_PrivilegedContainer(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata":   map[string]interface{}{"name": "test-job", "namespace": "default"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "worker",
							"image": "busybox:1.36",
							"securityContext": map[string]interface{}{
								"privileged": true,
							},
						},
					},
					"restartPolicy": "Never",
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-job-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-001" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Expected POL-SEC-001 violation for Job")
	}
}

func TestEvaluator_CronJob_PrivilegedContainer(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]interface{}{"name": "test-cronjob", "namespace": "default"},
		"spec": map[string]interface{}{
			"schedule": "*/5 * * * *",
			"jobTemplate": map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "worker",
									"image": "busybox:1.36",
									"securityContext": map[string]interface{}{
										"privileged": true,
									},
								},
							},
							"restartPolicy": "Never",
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-cronjob-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-001" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Expected POL-SEC-001 violation for CronJob")
	}
}

func TestEvaluator_CronJob_Safe(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]interface{}{"name": "safe-cronjob", "namespace": "default"},
		"spec": map[string]interface{}{
			"schedule": "0 * * * *",
			"jobTemplate": map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "worker",
									"image": "busybox:1.36.1",
									"securityContext": map[string]interface{}{
										"allowPrivilegeEscalation": false,
										"runAsNonRoot":             true,
										"privileged":               false,
									},
								},
							},
							"restartPolicy": "Never",
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-cronjob-002")

	if len(result.Violations) != 1 {
		t.Fatalf("Expected 1 advisory for safe CronJob, got %d", len(result.Violations))
	}
	if result.Status != decision.StatusAllowed {
		t.Fatalf("Expected ALLOWED status for safe CronJob, got %s", result.Status)
	}
	if findViolationByID(result.Violations, "ADV-NET-001") == nil {
		t.Fatal("Expected ADV-NET-001 advisory for safe CronJob")
	}
}

func TestEvaluator_ReplicaSet_HostPID(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "ReplicaSet",
		"metadata":   map[string]interface{}{"name": "hostpid-rs", "namespace": "default"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"hostPID": true,
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "worker",
							"image": "busybox:1.36.1",
							"securityContext": map[string]interface{}{
								"allowPrivilegeEscalation": false,
								"runAsNonRoot":             true,
							},
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rs-001")

	found := false
	for _, v := range result.Violations {
		if v.PolicyID == "POL-SEC-005" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Expected POL-SEC-005 violation for ReplicaSet")
	}
}

func TestEvaluator_CronJob_DoesNotTriggerRBACRules(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]interface{}{"name": "cronjob-no-rbac", "namespace": "default"},
		"spec": map[string]interface{}{
			"schedule": "*/10 * * * *",
			"jobTemplate": map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name":  "worker",
									"image": "busybox:1.36",
									"securityContext": map[string]interface{}{
										"privileged": true,
									},
								},
							},
							"restartPolicy": "Never",
						},
					},
				},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-cronjob-003")

	for _, v := range result.Violations {
		if strings.HasPrefix(v.PolicyID, "POL-RBAC-") {
			t.Fatalf("Expected no RBAC violations for CronJob, got %s", v.PolicyID)
		}
	}
}

func TestEvaluator_RoleBinding_DoesNotTriggerClusterAdminCheck(t *testing.T) {
	evaluator := New("v1alpha1")

	// RoleBinding (not ClusterRoleBinding) should NOT trigger POL-RBAC-004
	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]interface{}{"name": "rb-admin", "namespace": "default"},
		"roleRef": map[string]interface{}{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "cluster-admin",
		},
		"subjects": []interface{}{
			map[string]interface{}{
				"kind":      "ServiceAccount",
				"name":      "my-sa",
				"namespace": "default",
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-011")

	for _, v := range result.Violations {
		if v.PolicyID == "POL-RBAC-004" {
			t.Error("Expected no POL-RBAC-004 violation for RoleBinding (only applies to ClusterRoleBinding)")
		}
	}
}

func TestEvaluator_RBACResource_DoesNotGetNetworkPolicyAdvisory(t *testing.T) {
	evaluator := New("v1alpha1")

	spec := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": "reader", "namespace": "default"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods"},
				"verbs":     []interface{}{"get", "list"},
			},
		},
	}

	result := evaluator.Evaluate(spec, testTimestamp, "test-rbac-012")

	if findViolationByID(result.Violations, "ADV-NET-001") != nil {
		t.Fatal("Expected no ADV-NET-001 advisory for RBAC resource")
	}
}
