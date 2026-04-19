package output

import (
	"fmt"
	"strings"

	"github.com/opensource-alison/why-blocked/internal/decision"
	"github.com/opensource-alison/why-blocked/internal/detect"
	"github.com/opensource-alison/why-blocked/internal/i18n"
	"github.com/opensource-alison/why-blocked/internal/ui"
)

// RenderDecision formats a SecurityDecision as plain text for human consumption.
// If tr is nil, English is used.
func RenderDecision(d decision.SecurityDecision, tr *i18n.Translator) string {
	if tr == nil {
		tr, _ = i18n.New("en")
	}

	var b strings.Builder

	renderHeader(&b, d, tr)
	renderViolations(&b, d.Violations, tr)
	renderNextActions(&b, d.NextActions, tr)

	return b.String()
}

// RenderDiagnosis formats a detected block source and optional decision.
func RenderDiagnosis(source *detect.BlockSource, d *decision.SecurityDecision, tr *i18n.Translator) string {
	if tr == nil {
		tr, _ = i18n.New("en")
	}

	var b strings.Builder
	renderBlockSource(&b, source, tr)
	if d != nil {
		renderViolations(&b, d.Violations, tr)
		renderNextActions(&b, d.NextActions, tr)
	}
	return b.String()
}

func renderBlockSource(b *strings.Builder, source *detect.BlockSource, tr *i18n.Translator) {
	if source == nil {
		return
	}

	b.WriteString(ui.Bold(tr.T("diagnose.blocked_by", nil)))
	b.WriteString(" ")
	b.WriteString(colorConfidence(source.Engine, source.Confidence))
	b.WriteString("\n")

	if source.PolicyName != "" {
		b.WriteString("  ")
		b.WriteString(tr.T("diagnose.policy", nil))
		b.WriteString(" ")
		b.WriteString(source.PolicyName)
		b.WriteString("\n")
	}
	if source.RuleName != "" {
		b.WriteString("  ")
		b.WriteString(tr.T("diagnose.rule", nil))
		b.WriteString(" ")
		b.WriteString(source.RuleName)
		b.WriteString("\n")
	}

	b.WriteString("  ")
	b.WriteString(tr.T("diagnose.confidence", nil))
	b.WriteString(" ")
	b.WriteString(localizedConfidence(tr, source.Confidence))
	b.WriteString("\n\n")

	b.WriteString(ui.Bold(tr.T("diagnose.original_error", nil)))
	b.WriteString("\n")
	for _, line := range strings.Split(errorSnippet(source.RawMessage), "\n") {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if len(source.Hints) > 0 {
		b.WriteString(ui.Bold(tr.T("diagnose.next_steps", nil)))
		b.WriteString("\n")
		for _, hint := range source.Hints {
			b.WriteString("- ")
			b.WriteString(strings.TrimRight(localizedHint(tr, hint), "\n"))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
}

// renderHeader outputs the summary and metadata section.
func renderHeader(b *strings.Builder, d decision.SecurityDecision, tr *i18n.Translator) {
	summary := localizedDecisionSummary(d, tr)
	status := localizedStatus(tr, d.Status)
	b.WriteString(ui.Bold(tr.T("output.reason", map[string]any{"Summary": summary})) + "\n")
	b.WriteString(ui.Bold(tr.T("output.status", map[string]any{"Status": status})) + "\n")
	b.WriteString("\n")

	b.WriteString(tr.T("output.resource", map[string]any{"Kind": d.Resource.Kind, "Name": d.Resource.Name}) + "\n")
	if d.Resource.Namespace != "" {
		b.WriteString(tr.T("output.namespace", map[string]any{"Namespace": d.Resource.Namespace}) + "\n")
	}
	b.WriteString(tr.T("output.decision", map[string]any{"ID": d.ID}) + "\n")
	b.WriteString(tr.T("output.time", map[string]any{"Time": d.Timestamp.UTC().Format("2006-01-02T15:04:05Z")}) + "\n")
	b.WriteString("\n")
}

// renderViolations outputs the violations section with evidence and fixes.
func renderViolations(b *strings.Builder, violations []decision.Violation, tr *i18n.Translator) {
	if len(violations) == 0 {
		return
	}

	b.WriteString(ui.Bold(tr.T("section.violations", map[string]any{"Count": len(violations)})) + "\n")
	for i, v := range violations {
		title := resolveText(tr, v.TitleKey, v.TitleArgs, v.Title)
		severityColored := colorSeverity(v.Severity, tr)
		b.WriteString(fmt.Sprintf("%d) %s[%s] %s\n", i+1, severityPrefix(v.Severity), severityColored, title))

		// What: use MessageKey if present, else Message
		msg := resolveText(tr, v.MessageKey, v.MessageArgs, v.Message)
		if msg != "" {
			what := wrapIndent(msg, 80, "   ")
			b.WriteString(fmt.Sprintf("   %s %s\n", tr.T("label.what", nil), what))
		}

		// Evidence (field paths and raw values are NOT translated)
		if len(v.Evidence) > 0 {
			b.WriteString(fmt.Sprintf("   %s\n", tr.T("label.evidence", nil)))
			for _, e := range v.Evidence {
				evidenceDetail := resolveText(tr, e.DetailKey, e.DetailArgs, e.Detail)
				evidenceLine := fmt.Sprintf("(%s) %s: %s", e.Type, e.Subject, evidenceDetail)
				wrapped := wrapIndent(evidenceLine, 80, "     ")
				b.WriteString(fmt.Sprintf("     - %s\n", wrapped))
			}
		}

		// Fix
		if len(v.Fix) > 0 {
			b.WriteString(fmt.Sprintf("   %s\n", tr.T("label.fix", nil)))
			for _, f := range v.Fix {
				fixTitle := resolveText(tr, f.TitleKey, f.TitleArgs, f.Title)
				fixDetail := resolveText(tr, f.DetailKey, f.DetailArgs, f.Detail)
				fixLine := fixTitle
				if fixDetail != "" {
					fixLine = fmt.Sprintf("%s: %s", fixTitle, fixDetail)
				}
				wrapped := wrapIndent(fixLine, 80, "     ")
				b.WriteString(fmt.Sprintf("     - %s\n", wrapped))

				// Display FixExample if present
				if f.FixExample != "" {
					b.WriteString("       ")
					b.WriteString(tr.T("label.example", nil))
					b.WriteString("\n")
					for _, line := range strings.Split(f.FixExample, "\n") {
						b.WriteString(fmt.Sprintf("       %s\n", line))
					}
				}
			}
		}

		// Standards
		if len(v.Standards) > 0 {
			ids := make([]string, len(v.Standards))
			for j, s := range v.Standards {
				ids[j] = s.ID
			}
			b.WriteString(fmt.Sprintf("   %s %s\n", tr.T("label.standards", nil), strings.Join(ids, ", ")))
		}

		// Add blank line between violations
		if i < len(violations)-1 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
}

// renderNextActions outputs the next actions section.
func renderNextActions(b *strings.Builder, actions []decision.Action, tr *i18n.Translator) {
	if len(actions) == 0 {
		return
	}

	b.WriteString(ui.Bold(tr.T("section.nextActions", nil)) + "\n")
	// Show up to 4 items
	limit := len(actions)
	if limit > 4 {
		limit = 4
	}
	for i := 0; i < limit; i++ {
		a := actions[i]
		actionTitle := resolveText(tr, a.TitleKey, a.TitleArgs, a.Title)
		actionDetail := resolveText(tr, a.DetailKey, a.DetailArgs, a.Detail)
		actionLine := actionTitle
		if actionDetail != "" {
			actionLine = fmt.Sprintf("%s: %s", actionTitle, actionDetail)
		}
		wrapped := wrapIndent(actionLine, 80, "  ")
		b.WriteString(fmt.Sprintf("- %s\n", wrapped))
	}
}

// resolveText returns a translated string if key is non-empty, otherwise the fallback.
func resolveText(tr *i18n.Translator, key string, args map[string]string, fallback string) string {
	if key == "" {
		return fallback
	}
	return tr.T(key, toAnyMap(args))
}

// toAnyMap converts map[string]string to map[string]any for template execution.
func toAnyMap(m map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// colorSeverity applies color to severity levels for better visibility.
func colorSeverity(severity decision.Severity, tr *i18n.Translator) string {
	label := localizedSeverity(tr, severity)

	switch severity {
	case decision.SeverityCritical:
		return ui.Red(label)
	case decision.SeverityHigh:
		return ui.Yellow(label)
	case decision.SeverityMedium:
		return ui.Cyan(label)
	case decision.SeverityInfo:
		return ui.Blue(label)
	default:
		return label // LOW or unknown - no color
	}
}

func localizedSeverity(tr *i18n.Translator, severity decision.Severity) string {
	switch severity {
	case decision.SeverityInfo:
		return tr.T("severity.info", nil)
	case decision.SeverityLow:
		return tr.T("severity.low", nil)
	case decision.SeverityMedium:
		return tr.T("severity.medium", nil)
	case decision.SeverityHigh:
		return tr.T("severity.high", nil)
	case decision.SeverityCritical:
		return tr.T("severity.critical", nil)
	default:
		return string(severity)
	}
}

func localizedStatus(tr *i18n.Translator, status decision.DecisionStatus) string {
	switch status {
	case decision.StatusAllowed:
		return tr.T("status.allowed", nil)
	case decision.StatusBlocked:
		return tr.T("status.blocked", nil)
	default:
		return string(status)
	}
}

func localizedConfidence(tr *i18n.Translator, confidence string) string {
	switch confidence {
	case "high":
		return tr.T("diagnose.confidence.high", nil)
	case "medium":
		return tr.T("diagnose.confidence.medium", nil)
	case "low":
		return tr.T("diagnose.confidence.low", nil)
	default:
		return confidence
	}
}

func localizedDecisionSummary(d decision.SecurityDecision, tr *i18n.Translator) string {
	if d.SummaryKey != "" {
		return resolveText(tr, d.SummaryKey, d.SummaryArgs, d.Summary)
	}

	if d.Status == decision.StatusAllowed {
		infoCount := 0
		nonBlockingCount := 0
		for _, v := range d.Violations {
			switch v.Severity {
			case decision.SeverityInfo:
				infoCount++
				nonBlockingCount++
			case decision.SeverityLow:
				nonBlockingCount++
			}
		}

		switch {
		case infoCount == 1 && infoCount == nonBlockingCount:
			return tr.T("summary.allowed.advisory.one", nil)
		case infoCount > 1 && infoCount == nonBlockingCount:
			return tr.T("summary.allowed.advisory.many", map[string]any{"Count": infoCount})
		case nonBlockingCount > 0:
			return tr.T("summary.allowed.nonblocking", map[string]any{"Count": nonBlockingCount})
		default:
			return tr.T("summary.allowed.clean", nil)
		}
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, v := range d.Violations {
		switch v.Severity {
		case decision.SeverityCritical:
			criticalCount++
		case decision.SeverityHigh:
			highCount++
		case decision.SeverityMedium:
			mediumCount++
		}
	}

	var parts []string
	if criticalCount > 0 {
		parts = append(parts, tr.T("summary.part.critical", map[string]any{"Count": criticalCount}))
	}
	if highCount > 0 {
		parts = append(parts, tr.T("summary.part.high", map[string]any{"Count": highCount}))
	}
	if mediumCount > 0 {
		parts = append(parts, tr.T("summary.part.medium", map[string]any{"Count": mediumCount}))
	}
	if len(parts) == 0 {
		return resolveText(tr, d.SummaryKey, d.SummaryArgs, d.Summary)
	}

	return tr.T("summary.blocked", map[string]any{"Parts": strings.Join(parts, ", ")})
}

func localizedHint(tr *i18n.Translator, hint string) string {
	keys := map[string]string{
		"Check namespace PSA labels:":                                                             "diagnose.hint.psa.title",
		" kubectl get ns <namespace> -o yaml | grep pod-security":                                 "diagnose.hint.psa.command",
		"PSA documentation: https://kubernetes.io/docs/concepts/security/pod-security-admission/": "diagnose.hint.psa.docs",
		"Inspect the Kyverno policy:":                                                             "diagnose.hint.kyverno.title",
		" kubectl get clusterpolicy -o name":                                                      "diagnose.hint.kyverno.clusterpolicy",
		" kubectl get policy -n <namespace> -o name":                                              "diagnose.hint.kyverno.policy",
		"Kyverno docs: https://kyverno.io/docs/":                                                  "diagnose.hint.kyverno.docs",
		"List Gatekeeper constraints:":                                                            "diagnose.hint.gatekeeper.title",
		" kubectl get constraints":                                                                "diagnose.hint.gatekeeper.constraints",
		" kubectl get constrainttemplates":                                                        "diagnose.hint.gatekeeper.templates",
		"Gatekeeper docs: https://open-policy-agent.github.io/gatekeeper/":                        "diagnose.hint.gatekeeper.docs",
		"Check your RBAC permissions:":                                                            "diagnose.hint.rbac.title",
		" kubectl auth can-i <verb> <resource> --as=<user>":                                       "diagnose.hint.rbac.can_i",
		" kubectl get rolebindings,clusterrolebindings --all-namespaces | grep <user>":            "diagnose.hint.rbac.bindings",
		"List admission webhooks:":                                                                "diagnose.hint.webhook.title",
		" kubectl get validatingwebhookconfigurations":                                            "diagnose.hint.webhook.validating",
		" kubectl get mutatingwebhookconfigurations":                                              "diagnose.hint.webhook.mutating",
		"Could not identify the blocking system.":                                                 "diagnose.hint.unknown.title",
		"Check cluster events:":                                                                   "diagnose.hint.unknown.events",
		" kubectl get events --sort-by=.metadata.creationTimestamp":                               "diagnose.hint.unknown.command",
		"Check API server logs for more details.":                                                 "diagnose.hint.unknown.logs",
	}
	if key, ok := keys[hint]; ok {
		return tr.T(key, nil)
	}
	return hint
}

func severityPrefix(severity decision.Severity) string {
	if severity == decision.SeverityInfo {
		return "ℹ️ "
	}
	return ""
}

func colorConfidence(engine, confidence string) string {
	switch confidence {
	case "high":
		return ui.Red(engine)
	case "medium":
		return ui.Yellow(engine)
	default:
		return engine
	}
}

func errorSnippet(message string) string {
	const maxLines = 3
	const maxChars = 300

	snippet := truncateText(strings.TrimSpace(message), maxChars)
	lines := strings.Split(snippet, "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	return strings.Join(lines, "\n")
}

func truncateText(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// wrapIndent wraps text to the specified width, adding indent to continuation lines.
// The first line is NOT indented (caller handles that).
func wrapIndent(text string, width int, indent string) string {
	if len(text) <= width {
		return text
	}

	var result strings.Builder
	remaining := text
	firstLine := true

	for len(remaining) > 0 {
		if !firstLine {
			result.WriteString("\n")
			result.WriteString(indent)
		}

		// Determine how much to take
		takeLen := width
		if !firstLine {
			// Account for indent in width calculation
			takeLen = width - len(indent)
		}

		if len(remaining) <= takeLen {
			result.WriteString(remaining)
			break
		}

		// Find a good break point (space) before takeLen
		breakPoint := takeLen
		for i := takeLen; i > takeLen/2 && i < len(remaining); i-- {
			if remaining[i] == ' ' {
				breakPoint = i
				break
			}
		}

		// If no space found, just break at takeLen
		if breakPoint == takeLen && len(remaining) > takeLen {
			// Check if there's a space after takeLen
			spaceIdx := strings.IndexByte(remaining[takeLen:], ' ')
			if spaceIdx != -1 && spaceIdx < 20 {
				breakPoint = takeLen + spaceIdx
			}
		}

		result.WriteString(remaining[:breakPoint])
		remaining = strings.TrimSpace(remaining[breakPoint:])
		firstLine = false
	}

	return result.String()
}
