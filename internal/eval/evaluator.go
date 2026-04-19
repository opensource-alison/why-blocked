package eval

import (
	"fmt"
	"strings"
	"time"

	"github.com/opensource-alison/why-blocked/internal/decision"
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
	if hasBlockingViolations(violations) {
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
	resource := extractResourceRef(spec)

	// Pod-like resource checks
	podSpec := extractPodSpec(spec)
	if podSpec != nil {
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

		// Check for host PID namespace
		if v := checkHostPID(podSpec); v != nil {
			violations = append(violations, *v)
		}

		// Check for host network namespace
		if v := checkHostNetwork(podSpec); v != nil {
			violations = append(violations, *v)
		}

		// Check for host IPC namespace
		if v := checkHostIPC(podSpec); v != nil {
			violations = append(violations, *v)
		}

		// Check for dangerous Linux capabilities
		if v := checkDangerousCaps(podSpec); v != nil {
			violations = append(violations, *v)
		}

		// Check for allowPrivilegeEscalation not disabled
		if v := checkAllowPrivilegeEscalation(podSpec); v != nil {
			violations = append(violations, *v)
		}

		// Check for explicit root UID
		if v := checkRunAsRoot(podSpec); v != nil {
			violations = append(violations, *v)
		}

		if v := checkNetworkPolicyAdvisory(resource.Namespace); v != nil {
			violations = append(violations, *v)
		}
	}

	// RBAC resource checks
	kind, _ := spec["kind"].(string)
	if isRBACResource(kind) {
		for _, v := range checkRBACViolations(spec, kind) {
			violations = append(violations, *v)
		}
	}

	return violations
}

func hasBlockingViolations(violations []decision.Violation) bool {
	for _, v := range violations {
		switch v.Severity {
		case decision.SeverityCritical, decision.SeverityHigh, decision.SeverityMedium:
			return true
		}
	}
	return false
}

// extractPodSpec gets the pod template spec from a workload resource
func extractPodSpec(spec map[string]interface{}) map[string]interface{} {
	// For Pod resources
	if podSpec, ok := spec["spec"].(map[string]interface{}); ok {
		// Check if this is a Pod (has containers directly)
		if _, hasContainers := podSpec["containers"]; hasContainers {
			return podSpec
		}

		// For Deployment/StatefulSet/DaemonSet/Job/ReplicaSet (has template)
		if template, ok := podSpec["template"].(map[string]interface{}); ok {
			if templateSpec, ok := template["spec"].(map[string]interface{}); ok {
				return templateSpec
			}
		}

		// For CronJob (has jobTemplate.spec.template.spec)
		if jobTemplate, ok := podSpec["jobTemplate"].(map[string]interface{}); ok {
			if jobTemplateSpec, ok := jobTemplate["spec"].(map[string]interface{}); ok {
				if template, ok := jobTemplateSpec["template"].(map[string]interface{}); ok {
					if templateSpec, ok := template["spec"].(map[string]interface{}); ok {
						return templateSpec
					}
				}
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
				PolicyID:   "POL-SEC-001",
				Title:      "Privileged Container",
				TitleKey:   "violation.k8s.privileged.title",
				Severity:   decision.SeverityCritical,
				Message:    fmt.Sprintf("Container '%s' runs in privileged mode, which grants access to all host devices and bypasses security boundaries.", containerName),
				MessageKey: "violation.k8s.privileged.message",
				MessageArgs: map[string]string{
					"container": containerName,
				},
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: fieldPath,
						Detail:  "privileged: true",
					},
				},
				Fix: []decision.Action{
					{
						Title:     "Disable privileged mode",
						TitleKey:  "action.fix.disable_privileged.title",
						Detail:    fmt.Sprintf("Set securityContext.privileged: false for container '%s'", containerName),
						DetailKey: "action.fix.disable_privileged.detail",
						DetailArgs: map[string]string{
							"container": containerName,
						},
						FixExample: `containers:
 - name: my-container
   securityContext:
     privileged: false`,
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.2.1", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
					{ID: "PSA restricted", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"},
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
				PolicyID:   "POL-SEC-002",
				Title:      "HostPath Volume",
				TitleKey:   "violation.k8s.hostpath.title",
				Severity:   decision.SeverityHigh,
				Message:    fmt.Sprintf("Volume '%s' uses hostPath, which exposes host filesystem to the container.", volumeName),
				MessageKey: "violation.k8s.hostpath.message",
				MessageArgs: map[string]string{
					"volume": volumeName,
				},
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: fieldPath,
						Detail:  fmt.Sprintf("path: %s", path),
					},
				},
				Fix: []decision.Action{
					{
						Title:     "Use alternative volume type",
						TitleKey:  "action.fix.hostpath.title",
						Detail:    fmt.Sprintf("Replace hostPath volume '%s' with emptyDir, configMap, or persistent volume", volumeName),
						DetailKey: "action.fix.hostpath.detail",
						DetailArgs: map[string]string{
							"volume": volumeName,
						},
						FixExample: `# Remove the hostPath volume and use emptyDir or PVC instead
 volumes:
 - name: data
   emptyDir: {}`,
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.2.8", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
					{ID: "PSA baseline", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
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
				PolicyID:   "POL-SEC-003",
				Title:      "Missing runAsNonRoot",
				TitleKey:   "violation.k8s.runasnonroot.title",
				Severity:   decision.SeverityHigh,
				Message:    fmt.Sprintf("Container '%s' does not explicitly set runAsNonRoot: true, allowing potential root execution.", containerName),
				MessageKey: "violation.k8s.runasnonroot.message",
				MessageArgs: map[string]string{
					"container": containerName,
				},
				Evidence: []decision.Evidence{
					{
						Type:      decision.EvidenceK8sField,
						Subject:   fieldPath,
						Detail:    "runAsNonRoot not set or false",
						DetailKey: "evidence.k8s.runasnonroot.detail",
					},
				},
				Fix: []decision.Action{
					{
						Title:     "Set runAsNonRoot",
						TitleKey:  "action.fix.runasnonroot.title",
						Detail:    fmt.Sprintf("Add securityContext.runAsNonRoot: true for container '%s'", containerName),
						DetailKey: "action.fix.runasnonroot.detail",
						DetailArgs: map[string]string{
							"container": containerName,
						},
						FixExample: `securityContext:
   runAsNonRoot: true`,
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.2.6", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
					{ID: "PSA restricted", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"},
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
						FixExample: `containers:
 - name: my-container
   image: nginx:1.25.3  # use specific version tag`,
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.5.1", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
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
		infoCount := 0
		nonBlockingCount := 0
		for _, v := range violations {
			switch v.Severity {
			case decision.SeverityInfo:
				infoCount++
				nonBlockingCount++
			case decision.SeverityLow:
				nonBlockingCount++
			}
		}

		if infoCount > 0 && infoCount == nonBlockingCount {
			label := "advisories"
			if infoCount == 1 {
				label = "advisory"
			}
			return fmt.Sprintf("Resource meets security requirements with %d %s", infoCount, label)
		}
		if nonBlockingCount > 0 {
			return fmt.Sprintf("Resource meets security requirements with %d non-blocking findings", nonBlockingCount)
		}
		return "Resource meets security requirements"
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, v := range violations {
		switch v.Severity {
		case decision.SeverityCritical:
			criticalCount++
		case decision.SeverityHigh:
			highCount++
		case decision.SeverityMedium:
			mediumCount++
		}
	}

	parts := []string{}
	if criticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", criticalCount))
	}
	if highCount > 0 {
		parts = append(parts, fmt.Sprintf("%d high", highCount))
	}
	if mediumCount > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", mediumCount))
	}

	return fmt.Sprintf("Resource blocked: %s severity violations found", strings.Join(parts, ", "))
}

func checkNetworkPolicyAdvisory(namespace string) *decision.Violation {
	ns := namespace
	if ns == "" {
		ns = "default"
	}

	return &decision.Violation{
		PolicyID:    "ADV-NET-001",
		Title:       "NetworkPolicy not verified",
		TitleKey:    "adv_net_001_title",
		Severity:    decision.SeverityInfo,
		Message:     fmt.Sprintf("Cannot verify NetworkPolicy exists for namespace '%s' in offline mode", ns),
		MessageKey:  "adv_net_001_msg",
		MessageArgs: map[string]string{"Namespace": ns},
		Evidence: []decision.Evidence{
			{
				Type:      decision.EvidenceConfig,
				Subject:   "namespace/" + ns,
				Detail:    "NetworkPolicy presence cannot be checked without cluster access",
				DetailKey: "evidence.config.networkpolicy.detail",
			},
		},
		Fix: []decision.Action{
			{
				Title:      "Verify NetworkPolicy coverage",
				TitleKey:   "action.fix.networkpolicy.title",
				Detail:     fmt.Sprintf("Verify NetworkPolicy exists: kubectl get networkpolicy -n %s", ns),
				DetailKey:  "adv_net_001_fix",
				DetailArgs: map[string]string{"Namespace": ns},
				FixExample: fmt.Sprintf(`# Check existing NetworkPolicies:
kubectl get networkpolicy -n %s

# If none exist, create a default-deny policy:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`, ns, ns),
			},
		},
		Standards: []decision.StandardRef{
			{ID: "CIS 5.3.2", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
		},
	}
}

// checkHostPID checks for host PID namespace sharing
func checkHostPID(podSpec map[string]interface{}) *decision.Violation {
	hostPID, ok := podSpec["hostPID"].(bool)
	if !ok || !hostPID {
		return nil
	}
	return &decision.Violation{
		PolicyID:   "POL-SEC-005",
		Title:      "Host PID Namespace Shared",
		TitleKey:   "pol_sec_005_title",
		Severity:   decision.SeverityHigh,
		Message:    "Pod shares the host PID namespace, which allows containers to see and interact with all host processes.",
		MessageKey: "pol_sec_005_msg",
		Evidence: []decision.Evidence{
			{
				Type:    decision.EvidenceK8sField,
				Subject: "hostPID",
				Detail:  "hostPID is set to true",
			},
		},
		Fix: []decision.Action{
			{
				Title:    "Disable hostPID",
				TitleKey: "pol_sec_005_fix",
				Detail:   "Set spec.hostPID: false or remove it from the pod spec.",
				FixExample: `spec:
   hostPID: false  # or remove this field`,
			},
		},
		Standards: []decision.StandardRef{
			{ID: "CIS 5.2.2", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
			{ID: "PSA baseline", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		},
	}
}

// checkHostNetwork checks for host network namespace sharing
func checkHostNetwork(podSpec map[string]interface{}) *decision.Violation {
	hostNetwork, ok := podSpec["hostNetwork"].(bool)
	if !ok || !hostNetwork {
		return nil
	}
	return &decision.Violation{
		PolicyID:   "POL-SEC-006",
		Title:      "Host Network Namespace Shared",
		TitleKey:   "pol_sec_006_title",
		Severity:   decision.SeverityHigh,
		Message:    "Pod shares the host network namespace, which allows containers to sniff network traffic and access host network interfaces.",
		MessageKey: "pol_sec_006_msg",
		Evidence: []decision.Evidence{
			{
				Type:    decision.EvidenceK8sField,
				Subject: "hostNetwork",
				Detail:  "hostNetwork is set to true",
			},
		},
		Fix: []decision.Action{
			{
				Title:    "Disable hostNetwork",
				TitleKey: "pol_sec_006_fix",
				Detail:   "Set spec.hostNetwork: false or remove it from the pod spec.",
				FixExample: `spec:
   hostNetwork: false  # or remove this field`,
			},
		},
		Standards: []decision.StandardRef{
			{ID: "CIS 5.2.4", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
			{ID: "PSA baseline", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		},
	}
}

// checkHostIPC checks for host IPC namespace sharing
func checkHostIPC(podSpec map[string]interface{}) *decision.Violation {
	hostIPC, ok := podSpec["hostIPC"].(bool)
	if !ok || !hostIPC {
		return nil
	}
	return &decision.Violation{
		PolicyID:   "POL-SEC-007",
		Title:      "Host IPC Namespace Shared",
		TitleKey:   "pol_sec_007_title",
		Severity:   decision.SeverityHigh,
		Message:    "Pod shares the host IPC namespace, which allows containers to communicate with host processes via IPC mechanisms.",
		MessageKey: "pol_sec_007_msg",
		Evidence: []decision.Evidence{
			{
				Type:    decision.EvidenceK8sField,
				Subject: "hostIPC",
				Detail:  "hostIPC is set to true",
			},
		},
		Fix: []decision.Action{
			{
				Title:    "Disable hostIPC",
				TitleKey: "pol_sec_007_fix",
				Detail:   "Set spec.hostIPC: false or remove it from the pod spec.",
				FixExample: `spec:
   hostIPC: false  # or remove this field`,
			},
		},
		Standards: []decision.StandardRef{
			{ID: "CIS 5.2.3", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
			{ID: "PSA baseline", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
		},
	}
}

// dangerousCaps is the set of Linux capabilities considered dangerous.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN":  true,
	"SYS_PTRACE": true,
	"NET_ADMIN":  true,
	"SYS_RAWIO":  true,
	"NET_RAW":    true,
}

// checkDangerousCaps checks for containers that add dangerous Linux capabilities.
func checkDangerousCaps(podSpec map[string]interface{}) *decision.Violation {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}
	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		containerName := getContainerName(container)
		sc, ok := container["securityContext"].(map[string]interface{})
		if !ok {
			continue
		}
		caps, ok := sc["capabilities"].(map[string]interface{})
		if !ok {
			continue
		}
		addList, ok := caps["add"].([]interface{})
		if !ok {
			continue
		}
		for _, a := range addList {
			capStr, ok := a.(string)
			if !ok {
				continue
			}
			if dangerousCaps[capStr] {
				return &decision.Violation{
					PolicyID:   "POL-SEC-008",
					Title:      "Dangerous Linux Capability Added",
					TitleKey:   "pol_sec_008_title",
					Severity:   decision.SeverityHigh,
					Message:    fmt.Sprintf("Container '%s' adds dangerous Linux capability: %s.", containerName, capStr),
					MessageKey: "pol_sec_008_msg",
					MessageArgs: map[string]string{
						"container": containerName,
						"cap":       capStr,
					},
					Evidence: []decision.Evidence{
						{
							Type:    decision.EvidenceK8sField,
							Subject: containerName,
							Detail:  fmt.Sprintf("Container adds dangerous capability: %s", capStr),
						},
					},
					Fix: []decision.Action{
						{
							Title:    "Remove dangerous capability",
							TitleKey: "pol_sec_008_fix",
							Detail:   fmt.Sprintf("Remove '%s' from securityContext.capabilities.add for container '%s'.", capStr, containerName),
							FixExample: `securityContext:
   capabilities:
     drop:
     - ALL
     add: []  # remove dangerous capabilities`,
						},
					},
					Standards: []decision.StandardRef{
						{ID: "CIS 5.2.7", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
						{ID: "PSA restricted", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"},
					},
				}
			}
		}
	}
	return nil
}

// checkAllowPrivilegeEscalation checks that allowPrivilegeEscalation is explicitly disabled.
func checkAllowPrivilegeEscalation(podSpec map[string]interface{}) *decision.Violation {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}
	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		containerName := getContainerName(container)
		explicitlyDisabled := false
		if sc, ok := container["securityContext"].(map[string]interface{}); ok {
			if ape, ok := sc["allowPrivilegeEscalation"].(bool); ok && !ape {
				explicitlyDisabled = true
			}
		}
		if !explicitlyDisabled {
			return &decision.Violation{
				PolicyID:   "POL-SEC-009",
				Title:      "Privilege Escalation Not Disabled",
				TitleKey:   "pol_sec_009_title",
				Severity:   decision.SeverityMedium,
				Message:    fmt.Sprintf("Container '%s' does not explicitly set allowPrivilegeEscalation: false, which may allow processes to gain additional privileges.", containerName),
				MessageKey: "pol_sec_009_msg",
				MessageArgs: map[string]string{
					"container": containerName,
				},
				Evidence: []decision.Evidence{
					{
						Type:      decision.EvidenceK8sField,
						Subject:   containerName,
						Detail:    "allowPrivilegeEscalation is not explicitly set to false",
						DetailKey: "evidence.k8s.allowprivilegeescalation.detail",
					},
				},
				Fix: []decision.Action{
					{
						Title:     "Disable privilege escalation",
						TitleKey:  "pol_sec_009_fix",
						Detail:    fmt.Sprintf("Set securityContext.allowPrivilegeEscalation: false for container '%s'.", containerName),
						DetailKey: "action.fix.allowprivilegeescalation.detail",
						DetailArgs: map[string]string{
							"container": containerName,
						},
						FixExample: `securityContext:
   allowPrivilegeEscalation: false`,
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.2.5", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
					{ID: "PSA restricted", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"},
				},
			}
		}
	}
	return nil
}

// toUID converts an interface{} to a numeric UID, handling both float64 (YAML-parsed)
// and int (inline Go map) representations.
func toUID(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// checkRunAsRoot checks for containers or pods explicitly configured to run as UID 0.
func checkRunAsRoot(podSpec map[string]interface{}) *decision.Violation {
	// Container-level check takes priority
	containers, ok := podSpec["containers"].([]interface{})
	if ok {
		for _, c := range containers {
			container, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			containerName := getContainerName(container)
			if sc, ok := container["securityContext"].(map[string]interface{}); ok {
				if uid, ok := toUID(sc["runAsUser"]); ok && uid == 0 {
					return &decision.Violation{
						PolicyID:   "POL-SEC-010",
						Title:      "Container Runs as Root (UID 0)",
						TitleKey:   "pol_sec_010_title",
						Severity:   decision.SeverityHigh,
						Message:    fmt.Sprintf("Container '%s' explicitly runs as root (UID 0), which grants full administrative access.", containerName),
						MessageKey: "pol_sec_010_msg",
						MessageArgs: map[string]string{
							"container": containerName,
						},
						Evidence: []decision.Evidence{
							{
								Type:    decision.EvidenceK8sField,
								Subject: containerName,
								Detail:  "runAsUser is explicitly set to 0 (root)",
							},
						},
						Fix: []decision.Action{
							{
								Title:    "Run as non-root user",
								TitleKey: "pol_sec_010_fix",
								Detail:   fmt.Sprintf("Set securityContext.runAsUser to a non-zero UID for container '%s'.", containerName),
								FixExample: `securityContext:
   runAsUser: 1000  # use non-root UID
   runAsNonRoot: true`,
							},
						},
						Standards: []decision.StandardRef{
							{ID: "CIS 5.2.6", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
							{ID: "PSA restricted", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"},
						},
					}
				}
			}
		}
	}

	// Pod-level check
	if sc, ok := podSpec["securityContext"].(map[string]interface{}); ok {
		if uid, ok := toUID(sc["runAsUser"]); ok && uid == 0 {
			return &decision.Violation{
				PolicyID:   "POL-SEC-010",
				Title:      "Pod Runs as Root (UID 0)",
				TitleKey:   "pol_sec_010_title",
				Severity:   decision.SeverityHigh,
				Message:    "Pod is explicitly configured to run as root (UID 0), which grants full administrative access.",
				MessageKey: "pol_sec_010_msg",
				MessageArgs: map[string]string{
					"container": "pod",
				},
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceK8sField,
						Subject: "pod",
						Detail:  "runAsUser is explicitly set to 0 (root)",
					},
				},
				Fix: []decision.Action{
					{
						Title:    "Run as non-root user",
						TitleKey: "pol_sec_010_fix",
						Detail:   "Set spec.securityContext.runAsUser to a non-zero UID.",
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.2.6", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
					{ID: "PSA restricted", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"},
				},
			}
		}
	}

	return nil
}

// isRBACResource returns true for Role, ClusterRole, RoleBinding, ClusterRoleBinding.
func isRBACResource(kind string) bool {
	switch kind {
	case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding":
		return true
	}
	return false
}

// getMetaName extracts metadata.name from a resource spec.
func getMetaName(spec map[string]interface{}) string {
	if meta, ok := spec["metadata"].(map[string]interface{}); ok {
		if name, ok := meta["name"].(string); ok {
			return name
		}
	}
	return "unknown"
}

// containsStr reports whether list ([]interface{}) contains val as a string element.
func containsStr(list []interface{}, val string) bool {
	for _, item := range list {
		if s, ok := item.(string); ok && s == val {
			return true
		}
	}
	return false
}

// checkRBACViolations orchestrates all RBAC policy checks.
func checkRBACViolations(spec map[string]interface{}, kind string) []*decision.Violation {
	var violations []*decision.Violation

	if kind == "Role" || kind == "ClusterRole" {
		if v := checkWildcardRBAC(spec, kind); v != nil {
			violations = append(violations, v)
		}
		if v := checkSecretAccess(spec, kind); v != nil {
			violations = append(violations, v)
		}
		if v := checkPodExec(spec, kind); v != nil {
			violations = append(violations, v)
		}
	}

	if kind == "ClusterRoleBinding" {
		if v := checkClusterAdminBinding(spec); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

// checkWildcardRBAC detects Role/ClusterRole rules that use wildcard resources or verbs (POL-RBAC-001).
func checkWildcardRBAC(spec map[string]interface{}, kind string) *decision.Violation {
	name := getMetaName(spec)
	rules, _ := spec["rules"].([]interface{})
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		resources, _ := rule["resources"].([]interface{})
		verbs, _ := rule["verbs"].([]interface{})

		wildcardResources := containsStr(resources, "*")
		wildcardVerbs := containsStr(verbs, "*")

		if !wildcardResources && !wildcardVerbs {
			continue
		}

		what := "resources"
		if wildcardVerbs && !wildcardResources {
			what = "verbs"
		} else if wildcardResources && wildcardVerbs {
			what = "resources and verbs"
		}

		return &decision.Violation{
			PolicyID:   "POL-RBAC-001",
			Title:      "Wildcard Permissions",
			TitleKey:   "pol_rbac_001_title",
			Severity:   decision.SeverityCritical,
			Message:    fmt.Sprintf("%s '%s' uses wildcard permissions", kind, name),
			MessageKey: "pol_rbac_001_msg",
			MessageArgs: map[string]string{
				"kind": kind,
				"name": name,
			},
			Evidence: []decision.Evidence{
				{
					Type:    decision.EvidenceConfig,
					Subject: name,
					Detail:  fmt.Sprintf("%s uses wildcard %s", kind, what),
				},
			},
			Fix: []decision.Action{
				{
					Title:    "Replace wildcard with explicit permissions",
					TitleKey: "pol_rbac_001_fix",
					Detail:   "Replace wildcard with explicit resource names and verbs. Grant only the minimum permissions required.",
					FixExample: `rules:
 - apiGroups: [""]
   resources: ["pods", "services"]  # list specific resources
   verbs: ["get", "list", "watch"]  # list specific verbs`,
				},
			},
			Standards: []decision.StandardRef{
				{ID: "CIS 5.1.3", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
			},
		}
	}
	return nil
}

// checkSecretAccess detects Role/ClusterRole rules that grant unrestricted secret access (POL-RBAC-002).
func checkSecretAccess(spec map[string]interface{}, kind string) *decision.Violation {
	name := getMetaName(spec)
	rules, _ := spec["rules"].([]interface{})
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		resources, _ := rule["resources"].([]interface{})
		verbs, _ := rule["verbs"].([]interface{})
		resourceNames, _ := rule["resourceNames"].([]interface{})

		if !containsStr(resources, "secrets") {
			continue
		}
		if !containsStr(verbs, "get") && !containsStr(verbs, "list") {
			continue
		}
		if len(resourceNames) > 0 {
			continue
		}

		return &decision.Violation{
			PolicyID:   "POL-RBAC-002",
			Title:      "Unrestricted Secret Access",
			TitleKey:   "pol_rbac_002_title",
			Severity:   decision.SeverityHigh,
			Message:    fmt.Sprintf("%s '%s' grants unrestricted access to all secrets", kind, name),
			MessageKey: "pol_rbac_002_msg",
			MessageArgs: map[string]string{
				"kind": kind,
				"name": name,
			},
			Evidence: []decision.Evidence{
				{
					Type:    decision.EvidenceConfig,
					Subject: name,
					Detail:  fmt.Sprintf("%s grants unrestricted access to all secrets", kind),
				},
			},
			Fix: []decision.Action{
				{
					Title:    "Restrict secret access by name",
					TitleKey: "pol_rbac_002_fix",
					Detail:   "Add resourceNames to restrict access to specific secrets, or use a namespace-scoped Role to limit the blast radius.",
					FixExample: `rules:
 - apiGroups: [""]
   resources: ["secrets"]
   verbs: ["get"]
   resourceNames: ["my-specific-secret"]`,
				},
			},
			Standards: []decision.StandardRef{
				{ID: "CIS 5.1.2", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
			},
		}
	}
	return nil
}

// checkPodExec detects Role/ClusterRole rules that grant pods/exec create access (POL-RBAC-003).
func checkPodExec(spec map[string]interface{}, kind string) *decision.Violation {
	name := getMetaName(spec)
	rules, _ := spec["rules"].([]interface{})
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		resources, _ := rule["resources"].([]interface{})
		verbs, _ := rule["verbs"].([]interface{})

		if containsStr(resources, "pods/exec") && containsStr(verbs, "create") {
			return &decision.Violation{
				PolicyID:   "POL-RBAC-003",
				Title:      "pods/exec Permission Granted",
				TitleKey:   "pol_rbac_003_title",
				Severity:   decision.SeverityHigh,
				Message:    fmt.Sprintf("%s '%s' allows exec into pods", kind, name),
				MessageKey: "pol_rbac_003_msg",
				MessageArgs: map[string]string{
					"kind": kind,
					"name": name,
				},
				Evidence: []decision.Evidence{
					{
						Type:    decision.EvidenceConfig,
						Subject: name,
						Detail:  fmt.Sprintf("%s grants pods/exec create access", kind),
					},
				},
				Fix: []decision.Action{
					{
						Title:    "Remove pods/exec create permission",
						TitleKey: "pol_rbac_003_fix",
						Detail:   "Remove pods/exec create permission unless explicitly required for debugging. Consider using ephemeral containers instead.",
						FixExample: `# Remove pods/exec rule, or restrict to specific pods:
 rules:
 - apiGroups: [""]
   resources: ["pods"]
   verbs: ["get", "list"]
   # pods/exec rule removed`,
					},
				},
				Standards: []decision.StandardRef{
					{ID: "CIS 5.1.3", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
				},
			}
		}
	}
	return nil
}

// checkClusterAdminBinding detects ClusterRoleBindings that grant cluster-admin (POL-RBAC-004).
func checkClusterAdminBinding(spec map[string]interface{}) *decision.Violation {
	name := getMetaName(spec)

	roleRef, _ := spec["roleRef"].(map[string]interface{})
	roleRefName, _ := roleRef["name"].(string)
	roleRefKind, _ := roleRef["kind"].(string)

	if roleRefName != "cluster-admin" || roleRefKind != "ClusterRole" {
		return nil
	}

	// Get first subject name for evidence
	subjectName := "unknown"
	if subjects, ok := spec["subjects"].([]interface{}); ok && len(subjects) > 0 {
		if subject, ok := subjects[0].(map[string]interface{}); ok {
			if sName, ok := subject["name"].(string); ok {
				subjectName = sName
			}
		}
	}

	return &decision.Violation{
		PolicyID:   "POL-RBAC-004",
		Title:      "ClusterRoleBinding to cluster-admin",
		TitleKey:   "pol_rbac_004_title",
		Severity:   decision.SeverityCritical,
		Message:    fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin to '%s'", name, subjectName),
		MessageKey: "pol_rbac_004_msg",
		MessageArgs: map[string]string{
			"name":    name,
			"subject": subjectName,
		},
		Evidence: []decision.Evidence{
			{
				Type:    decision.EvidenceConfig,
				Subject: subjectName,
				Detail:  fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin to '%s'", name, subjectName),
			},
		},
		Fix: []decision.Action{
			{
				Title:    "Replace cluster-admin binding with scoped role",
				TitleKey: "pol_rbac_004_fix",
				Detail:   "Create a scoped ClusterRole with only required permissions and bind it instead of cluster-admin.",
				FixExample: `# Replace cluster-admin with a scoped ClusterRole:
 roleRef:
   apiGroup: rbac.authorization.k8s.io
   kind: ClusterRole
   name: my-limited-role  # not cluster-admin`,
			},
		},
		Standards: []decision.StandardRef{
			{ID: "CIS 5.1.1", URL: "https://www.cisecurity.org/benchmark/kubernetes"},
		},
	}
}

// buildNextActions suggests remediation steps
func buildNextActions(violations []decision.Violation) []decision.Action {
	if len(violations) == 0 || !hasBlockingViolations(violations) {
		return nil
	}

	return []decision.Action{
		{
			Title:     "Review violations",
			TitleKey:  "next_action.review_violations.title",
			Detail:    "Address the security violations listed above to meet policy requirements",
			DetailKey: "next_action.review_violations.detail",
		},
	}
}
