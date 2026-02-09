package output

import (
	"fmt"
	"strings"

	"github.com/alisonui/why-blocked/internal/decision"
	"github.com/alisonui/why-blocked/internal/i18n"
	"github.com/alisonui/why-blocked/internal/ui"
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

// renderHeader outputs the summary and metadata section.
func renderHeader(b *strings.Builder, d decision.SecurityDecision, tr *i18n.Translator) {
	summary := resolveText(tr, d.SummaryKey, d.SummaryArgs, d.Summary)
	b.WriteString(ui.Bold(tr.T("output.reason", map[string]any{"Summary": summary})) + "\n")
	b.WriteString(ui.Bold(tr.T("output.status", map[string]any{"Status": d.Status})) + "\n")
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
		severityColored := colorSeverity(string(v.Severity))
		b.WriteString(fmt.Sprintf("%d) [%s] %s\n", i+1, severityColored, title))

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
				evidenceLine := fmt.Sprintf("(%s) %s: %s", e.Type, e.Subject, e.Detail)
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
			}
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
func colorSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return ui.Red(severity)
	case "HIGH":
		return ui.Yellow(severity)
	case "MEDIUM":
		return ui.Cyan(severity)
	default:
		return severity // LOW or unknown - no color
	}
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
