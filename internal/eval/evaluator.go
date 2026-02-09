package eval

import (
	"fmt"
	"strings"
	"time"

	"github.com/alisonui/why-blocked/internal/decision"
)

// Evaluator checks Kubernetes resources against security policies.
type Evaluator struct {
	version string
}

// New creates a new Evaluator with the given schema version.
func New(version string) *Evaluator {
	return &Evaluator{
		version: version,
	}
}

// Evaluate takes a Kubernetes resource (as a generic map structure) and returns a SecurityDecision.
// The spec map should represent a Kubernetes resource like a Deployment, Pod, etc.
func (e *Evaluator) Evaluate(spec map[string]interface{}, timestamp time.Time, decisionID string) decision.SecurityDecision {
	// Extract resource metadata
	resource := extractResourceRef(spec)

	// Check for violations
	violations := e.checkViolations(spec)

	// Determine status
	status := decision.StatusAllowed
	if len(violations) > 0 {
		status = decision.StatusBlocked
	}

	// Build summary
	summary := buildSummary(status, violations)

	d := decision.SecurityDecision{
		ID:        decisionID,
		Timestamp: timestamp,
		Resource:  resource,
		Status:    status,
		Summary:   summary,
		Version:   e.version,
	}

	if len(violations) > 0 {
		d.Violations = violations
		d.NextActions = buildNextActions(violations)
	}

	return d
}

// extractResourceRef extracts resource identification from the spec
func extractResourceRef(spec map[string]interface{}) decision.ResourceRef {
	ref := decision.ResourceRef{
		Kind:      "Deployment",
		Name:      "unknown",
		Namespace: "default",
	}

	if kind, ok := spec["kind"].(string); ok {
		ref.Kind = kind
	}

	if apiVersion, ok := spec["apiVersion"].(string); ok {
		ref.APIVersion = apiVersion
	}

	if metadata, ok := spec["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			ref.Name = name
		}
		if namespace, ok := metadata["namespace"].(string); ok {
			ref.Namespace = namespace
		}
	}

	return ref
}

// checkViolations runs all policy checks against the spec
func (e *Evaluator) checkViolations(spec map[string]interface{}) []decision.Violation {
	var violations []decision.Violation

	// Get the pod template spec (works for Deployment, DaemonSet, StatefulSet, etc.)
	podSpec := extractPodSpec(spec)
	if podSpec == nil {
		return violations
	}

	// Check for privileged containers
	if v := checkPrivileged(podSpec); v != nil {
		violations = append(violations, *v)
	}

	// Check for hostPath volumes
	if v := checkHostPath(podSpec); v != nil {
		violations = append(violations, *v)
	}

	// Check for runAsNonRoot
	if v := checkRunAsNonRoot(podSpec); v != nil {
		violations = append(violations, *v)
	}

	// Check for latest tag
	if v := checkLatestTag(podSpec); v != nil {
		violations = append(violations, *v)
	}

	return violations
}

// extractPodSpec gets the pod template spec from a workload resource
func extractPodSpec(spec map[string]interface{}) map[string]interface{} {
	// For Pod resources
	if podSpec, ok := spec["spec"].(map[string]interface{}); ok {
		// Check if this is a Pod (has containers directly)
		if _, hasContainers := podSpec["containers"]; hasContainers {
			return podSpec
		}

		// For Deployment/StatefulSet/DaemonSet (has template)
		if template, ok := podSpec["template"].(map[string]interface{}); ok {
			if templateSpec, ok := template["spec"].(map[string]interface{}); ok {
				return templateSpec
			}
		}
	}

	return nil
}

// checkPrivileged checks for privileged containers
func checkPrivileged(podSpec map[string]interface{}) *decision.Violation {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	for i, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		containerName := getContainerName(container)

		securityContext, ok := container["securityContext"].(map[string]interface{})
		if !ok {
			continue
		}

		privileged, ok := securityContext["privileged"].(bool)
		if ok && privileged {
			fieldPath := fmt.Sprintf("spec.template.spec.containers[%d].securityContext.privileged", i)

			return &decision.Violation{
				PolicyID: "POL-SEC-001",
				Title:    "Privileged Container",
				TitleKey: "violation.k8s.privileged.title",
				Severity: decision.SeverityCritical,
				Message:  fmt.Sprintf("Container '%s' runs in privileged mode, which grants access to all host devices and bypasses security boundaries.", containerName),
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: fieldPath,
						Detail:  "privileged: true",
					},
				},
				Fix: []decision.Action{
					{
						Title:  "Disable privileged mode",
						Detail: fmt.Sprintf("Set securityContext.privileged: false for container '%s'", containerName),
					},
				},
			}
		}
	}

	return nil
}

// checkHostPath checks for hostPath volumes
func checkHostPath(podSpec map[string]interface{}) *decision.Violation {
	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		return nil
	}

	for i, v := range volumes {
		volume, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		if hostPath, ok := volume["hostPath"].(map[string]interface{}); ok {
			volumeName := "unknown"
			if name, ok := volume["name"].(string); ok {
				volumeName = name
			}

			path := ""
			if p, ok := hostPath["path"].(string); ok {
				path = p
			}

			fieldPath := fmt.Sprintf("spec.template.spec.volumes[%d].hostPath", i)

			return &decision.Violation{
				PolicyID: "POL-SEC-002",
				Title:    "HostPath Volume",
				TitleKey: "violation.k8s.hostpath.title",
				Severity: decision.SeverityHigh,
				Message:  fmt.Sprintf("Volume '%s' uses hostPath, which exposes host filesystem to the container.", volumeName),
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: fieldPath,
						Detail:  fmt.Sprintf("path: %s", path),
					},
				},
				Fix: []decision.Action{
					{
						Title:  "Use alternative volume type",
						Detail: fmt.Sprintf("Replace hostPath volume '%s' with emptyDir, configMap, or persistent volume", volumeName),
					},
				},
			}
		}
	}

	return nil
}

// checkRunAsNonRoot checks if runAsNonRoot is set
func checkRunAsNonRoot(podSpec map[string]interface{}) *decision.Violation {
	// Check pod-level securityContext first
	if securityContext, ok := podSpec["securityContext"].(map[string]interface{}); ok {
		if runAsNonRoot, ok := securityContext["runAsNonRoot"].(bool); ok && runAsNonRoot {
			// Pod-level is set correctly, no violation
			return nil
		}
	}

	// Check container-level
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	// If any container doesn't have runAsNonRoot set or set to false, it's a violation
	for i, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		containerName := getContainerName(container)
		hasRunAsNonRoot := false

		if securityContext, ok := container["securityContext"].(map[string]interface{}); ok {
			if runAsNonRoot, ok := securityContext["runAsNonRoot"].(bool); ok && runAsNonRoot {
				hasRunAsNonRoot = true
			}
		}

		if !hasRunAsNonRoot {
			fieldPath := fmt.Sprintf("spec.template.spec.containers[%d].securityContext.runAsNonRoot", i)

			return &decision.Violation{
				PolicyID: "POL-SEC-003",
				Title:    "Missing runAsNonRoot",
				TitleKey: "violation.k8s.runasnonroot.title",
				Severity: decision.SeverityHigh,
				Message:  fmt.Sprintf("Container '%s' does not explicitly set runAsNonRoot: true, allowing potential root execution.", containerName),
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: fieldPath,
						Detail:  "runAsNonRoot not set or false",
					},
				},
				Fix: []decision.Action{
					{
						Title:  "Set runAsNonRoot",
						Detail: fmt.Sprintf("Add securityContext.runAsNonRoot: true for container '%s'", containerName),
					},
				},
			}
		}
	}

	return nil
}

// checkLatestTag checks for :latest or missing image tags
func checkLatestTag(podSpec map[string]interface{}) *decision.Violation {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	for i, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		image, ok := container["image"].(string)
		if !ok {
			continue
		}

		containerName := getContainerName(container)

		// Check if image has :latest tag or no tag at all
		if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
			fieldPath := fmt.Sprintf("spec.template.spec.containers[%d].image", i)

			return &decision.Violation{
				PolicyID: "POL-SEC-004",
				Title:    "Latest Image Tag",
				TitleKey: "violation.image.latest.title",
				Severity: decision.SeverityHigh,
				Message:  fmt.Sprintf("Container '%s' uses image '%s' with 'latest' tag or no tag, which is not immutable.", containerName, image),
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: fieldPath,
						Detail:  image,
					},
				},
				Fix: []decision.Action{
					{
						Title:  "Use specific image tag",
						Detail: fmt.Sprintf("Replace image '%s' with a specific version tag or SHA digest", image),
					},
				},
			}
		}
	}

	return nil
}

// getContainerName safely extracts container name
func getContainerName(container map[string]interface{}) string {
	if name, ok := container["name"].(string); ok {
		return name
	}
	return "unknown"
}

// buildSummary creates a human-readable summary
func buildSummary(status decision.DecisionStatus, violations []decision.Violation) string {
	if status == decision.StatusAllowed {
		return "Resource meets security requirements"
	}

	criticalCount := 0
	highCount := 0

	for _, v := range violations {
		switch v.Severity {
		case decision.SeverityCritical:
			criticalCount++
		case decision.SeverityHigh:
			highCount++
		}
	}

	parts := []string{}
	if criticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", criticalCount))
	}
	if highCount > 0 {
		parts = append(parts, fmt.Sprintf("%d high", highCount))
	}

	return fmt.Sprintf("Resource blocked: %s severity violations found", strings.Join(parts, ", "))
}

// buildNextActions suggests remediation steps
func buildNextActions(violations []decision.Violation) []decision.Action {
	if len(violations) == 0 {
		return nil
	}

	return []decision.Action{
		{
			Title:  "Review violations",
			Detail: "Address the security violations listed above to meet policy requirements",
		},
	}
}
