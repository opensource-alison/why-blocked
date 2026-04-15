package detect

import "strings"

// BlockSource describes which admission system blocked a resource.
type BlockSource struct {
	Engine     string   `json:"engine"`
	PolicyName string   `json:"policyName,omitempty"`
	RuleName   string   `json:"ruleName,omitempty"`
	RawMessage string   `json:"rawMessage"`
	Confidence string   `json:"confidence"`
	Hints      []string `json:"hints,omitempty"`
}

// DetectBlockSource identifies the admission system that blocked a resource.
func DetectBlockSource(errorText string) *BlockSource {
	trimmed := strings.TrimSpace(errorText)

	if isPSA(trimmed) {
		return &BlockSource{
			Engine:     "PSA",
			PolicyName: extractPSALevel(trimmed),
			RawMessage: truncate(trimmed, 500),
			Confidence: "high",
			Hints: []string{
				"Check namespace PSA labels:",
				" kubectl get ns <namespace> -o yaml | grep pod-security",
				"PSA documentation: https://kubernetes.io/docs/concepts/security/pod-security-admission/",
			},
		}
	}

	if isKyverno(trimmed) {
		policyName, ruleName := extractKyvernoNames(trimmed)
		return &BlockSource{
			Engine:     "Kyverno",
			PolicyName: policyName,
			RuleName:   ruleName,
			RawMessage: truncate(trimmed, 500),
			Confidence: "high",
			Hints: []string{
				"Inspect the Kyverno policy:",
				" kubectl get clusterpolicy -o name",
				" kubectl get policy -n <namespace> -o name",
				"Kyverno docs: https://kyverno.io/docs/",
			},
		}
	}

	if isGatekeeper(trimmed) {
		return &BlockSource{
			Engine:     "Gatekeeper",
			PolicyName: extractGatekeeperConstraint(trimmed),
			RawMessage: truncate(trimmed, 500),
			Confidence: "high",
			Hints: []string{
				"List Gatekeeper constraints:",
				" kubectl get constraints",
				" kubectl get constrainttemplates",
				"Gatekeeper docs: https://open-policy-agent.github.io/gatekeeper/",
			},
		}
	}

	if isRBAC(trimmed) {
		return &BlockSource{
			Engine:     "RBAC",
			PolicyName: extractRBACAction(trimmed),
			RawMessage: truncate(trimmed, 500),
			Confidence: "high",
			Hints: []string{
				"Check your RBAC permissions:",
				" kubectl auth can-i <verb> <resource> --as=<user>",
				" kubectl get rolebindings,clusterrolebindings --all-namespaces | grep <user>",
			},
		}
	}

	if isGenericWebhook(trimmed) {
		return &BlockSource{
			Engine:     "Webhook",
			PolicyName: extractQuoted(trimmed, "webhook"),
			RawMessage: truncate(trimmed, 500),
			Confidence: "medium",
			Hints: []string{
				"List admission webhooks:",
				" kubectl get validatingwebhookconfigurations",
				" kubectl get mutatingwebhookconfigurations",
			},
		}
	}

	return &BlockSource{
		Engine:     "Unknown",
		RawMessage: truncate(trimmed, 500),
		Confidence: "low",
		Hints: []string{
			"Could not identify the blocking system.",
			"Check cluster events:",
			" kubectl get events --sort-by=.metadata.creationTimestamp",
			"Check API server logs for more details.",
		},
	}
}

func isPSA(text string) bool {
	return strings.Contains(text, "violates PodSecurity")
}

func isKyverno(text string) bool {
	if strings.Contains(text, "validate.kyverno.svc") {
		return true
	}

	return containsIgnoreCase(text, "kyverno") &&
		(containsIgnoreCase(text, "validation error") || containsIgnoreCase(text, "rule"))
}

func isGatekeeper(text string) bool {
	return containsIgnoreCase(text, "denied by constraint") ||
		containsIgnoreCase(text, "gatekeeper") ||
		(containsIgnoreCase(text, "constraint") && containsIgnoreCase(text, "violation"))
}

func isRBAC(text string) bool {
	return containsIgnoreCase(text, "forbidden") &&
		(strings.Contains(text, "User") || strings.Contains(text, "ServiceAccount")) &&
		containsIgnoreCase(text, "cannot")
}

func isGenericWebhook(text string) bool {
	return containsIgnoreCase(text, "denied the request") ||
		(containsIgnoreCase(text, "admission webhook") && containsIgnoreCase(text, "denied")) ||
		(containsIgnoreCase(text, "webhook") && containsIgnoreCase(text, "denied"))
}

func extractPSALevel(text string) string {
	quoted := extractQuoted(text, "violates PodSecurity")
	if quoted == "" {
		return ""
	}

	parts := strings.SplitN(quoted, ":", 2)
	return strings.TrimSpace(parts[0])
}

func extractKyvernoNames(text string) (string, string) {
	policy := extractResourceName(text, "ClusterPolicy/")
	if policy == "" {
		policy = extractResourceName(text, "Policy/")
	}
	if policy == "" {
		policy = extractTokenAfter(text, "policy ")
	}

	rule := extractTokenAfter(text, "rule ")

	lines := strings.Split(text, "\n")
	inPolicyBlock := false
	foundPolicyLine := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if !inPolicyBlock && containsIgnoreCase(trimmed, "following policies") {
			inPolicyBlock = true
			continue
		}

		if !inPolicyBlock {
			continue
		}

		if !foundPolicyLine && strings.HasSuffix(trimmed, ":") {
			foundPolicyLine = true
			if policy == "" {
				policy = strings.TrimSuffix(trimmed, ":")
			}
			continue
		}

		if foundPolicyLine && rule == "" && strings.HasSuffix(trimmed, ":") {
			rule = strings.TrimSuffix(trimmed, ":")
			break
		}
	}

	return strings.TrimSpace(policy), strings.TrimSpace(rule)
}

func extractGatekeeperConstraint(text string) string {
	if bracketed := extractBetween(text, "[", "]"); bracketed != "" {
		return strings.TrimSpace(strings.TrimPrefix(bracketed, "denied by "))
	}

	return extractTokenAfter(text, "constraint ")
}

func extractRBACAction(text string) string {
	if action := extractBetween(text, " cannot ", " in API group "); action != "" {
		return action
	}
	if action := extractBetween(text, "cannot ", " in API group "); action != "" {
		return action
	}
	if action := extractBetween(text, "cannot ", " in the namespace "); action != "" {
		return action
	}

	return ""
}

func extractResourceName(text, marker string) string {
	index := strings.Index(text, marker)
	if index == -1 {
		return ""
	}

	start := index + len(marker)
	end := start
	for end < len(text) {
		switch text[end] {
		case ' ', '\n', '\r', '\t', ':', ',', '\'', '"', ')', '(':
			return strings.TrimSpace(text[start:end])
		default:
			end++
		}
	}

	return strings.TrimSpace(text[start:end])
}

func extractTokenAfter(text, marker string) string {
	index := indexIgnoreCase(text, marker)
	if index == -1 {
		return ""
	}

	start := index + len(marker)
	for start < len(text) && (text[start] == ' ' || text[start] == '"' || text[start] == '\'') {
		start++
	}

	end := start
	for end < len(text) {
		switch text[end] {
		case ' ', '\n', '\r', '\t', ':', ',', '\'', '"', ')', '(':
			return strings.TrimSpace(text[start:end])
		default:
			end++
		}
	}

	return strings.TrimSpace(text[start:end])
}

func indexIgnoreCase(s, substr string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(substr))
}

// extractBetween finds text between 'before' and 'after' markers.
func extractBetween(text, before, after string) string {
	start := strings.Index(text, before)
	if start == -1 {
		return ""
	}

	start += len(before)
	end := strings.Index(text[start:], after)
	if end == -1 {
		return ""
	}

	return strings.TrimSpace(text[start : start+end])
}

// extractQuoted finds the first quoted string after a marker.
func extractQuoted(text, marker string) string {
	start := indexIgnoreCase(text, marker)
	if start == -1 {
		return ""
	}

	rest := text[start+len(marker):]
	firstQuote := strings.Index(rest, "\"")
	if firstQuote == -1 {
		return ""
	}

	rest = rest[firstQuote+1:]
	secondQuote := strings.Index(rest, "\"")
	if secondQuote == -1 {
		return ""
	}

	return strings.TrimSpace(rest[:secondQuote])
}

// truncate limits string length.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// containsIgnoreCase is a case-insensitive Contains.
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
