package decision

import (
	"time"
)

// ExampleBlockedDecision returns a realistic example of a blocked deployment decision.
func ExampleBlockedDecision() SecurityDecision {
	return SecurityDecision{
		ID:         "dec-7721",
		Timestamp:  time.Date(2026, 2, 5, 16, 0, 0, 0, time.UTC),
		Version:    "v1alpha1",
		Status:     StatusBlocked,
		Summary:    "Deployment blocked due to critical security violations",
		SummaryKey: "decision.summary.blocked_critical",
		Resource: ResourceRef{
			Kind:       "Deployment",
			Name:       "nginx-ingress",
			Namespace:  "production",
			APIVersion: "apps/v1",
		},
		Violations: []Violation{
			{
				PolicyID:   "POL-SEC-001",
				Title:      "Privileged Container",
				TitleKey:   "violation.k8s.privileged.title",
				Severity:   SeverityCritical,
				Message:    "Containers must not run as privileged. Found privileged: true in container 'nginx'.",
				MessageKey: "violation.k8s.privileged.message",
				MessageArgs: map[string]string{
					"container": "nginx",
					"fieldPath": "spec.template.spec.containers[0].securityContext.privileged",
					"value":     "true",
				},
				Evidence: []Evidence{
					{
						Type:    EvidenceK8sField,
						Subject: "spec.template.spec.containers[0].securityContext.privileged",
						Detail:  "Field is explicitly set to true, which bypasses all container security boundaries.",
					},
				},
				Fix: []Action{
					{
						Title:     "Disable privileged mode",
						TitleKey:  "action.fix.disable_privileged.title",
						Detail:    "Set securityContext.privileged: false in the container spec.",
						DetailKey: "action.fix.disable_privileged.detail",
						DetailArgs: map[string]string{
							"container": "nginx",
						},
						Patch: PatchSuggestion{
							Format:  "strategic-merge",
							Content: `{"spec": {"template": {"spec": {"containers": [{"name": "nginx", "securityContext": {"privileged": false}}]}}}}`,
						},
					},
				},
			},
			{
				PolicyID:   "POL-SEC-005",
				Title:      "Insecure Image Usage",
				TitleKey:   "violation.image.latest.title",
				Severity:   SeverityHigh,
				Message:    "Deployment uses image with critical vulnerabilities or insecure tags.",
				MessageKey: "violation.image.latest.message",
				MessageArgs: map[string]string{
					"image":    "nginx:latest",
					"tag":      "latest",
					"cveCount": "3",
				},
				Evidence: []Evidence{
					{
						Type:    EvidenceImageScan,
						Subject: "nginx:latest",
						Detail:  "Image uses 'latest' tag which is not immutable and contains 3 critical CVEs (CVE-2023-1234, ...).",
					},
				},
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
				},
			},
		},
		NextActions: []Action{
			{
				Title:     "Update deployment manifest",
				TitleKey:  "action.next.update_manifest.title",
				Detail:    "Apply the suggested patches to meet security requirements.",
				DetailKey: "action.next.update_manifest.detail",
			},
			{
				Title:     "Scan image locally",
				TitleKey:  "action.next.scan_image.title",
				Detail:    "Use 'trivy image nginx:latest' to see full vulnerability report.",
				DetailKey: "action.next.scan_image.detail",
				DetailArgs: map[string]string{
					"image": "nginx:latest",
				},
			},
		},
		Metadata: map[string]string{
			"cluster-id": "prod-cluster-01",
			"checker":    "admission-webhook-v2",
		},
	}
}
