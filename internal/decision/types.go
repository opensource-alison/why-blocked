package decision

import (
	"time"
)

// DecisionStatus represents the outcome of a security check.
type DecisionStatus string

const (
	StatusBlocked DecisionStatus = "BLOCKED"
	StatusAllowed DecisionStatus = "ALLOWED"
)

// Severity represents the level of risk associated with a violation.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// EvidenceType categorizes the source or kind of evidence provided.
type EvidenceType string

const (
	EvidenceK8sField  EvidenceType = "K8S_FIELD"
	EvidenceImageScan EvidenceType = "IMAGE_SCAN"
	EvidenceSbom      EvidenceType = "SBOM"
	EvidenceOther     EvidenceType = "OTHER"
)

// SecurityDecision is the single source of truth for explaining why a resource was blocked or allowed.
type SecurityDecision struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Resource    ResourceRef       `json:"resource"`
	Status      DecisionStatus    `json:"status"`
	Summary     string            `json:"summary"`
	SummaryKey  string            `json:"summaryKey,omitempty"`
	SummaryArgs map[string]string `json:"summaryArgs,omitempty"`
	Violations  []Violation       `json:"violations,omitempty"`
	NextActions []Action          `json:"nextActions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Version     string            `json:"version"`
}

// ResourceRef identifies the Kubernetes resource being evaluated.
type ResourceRef struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	UID        string `json:"uid,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
}

// Violation describes a specific policy breach.
type Violation struct {
	PolicyID    string            `json:"policyId"`
	Title       string            `json:"title"`
	TitleKey    string            `json:"titleKey,omitempty"`
	TitleArgs   map[string]string `json:"titleArgs,omitempty"`
	Severity    Severity          `json:"severity"`
	Message     string            `json:"message"`
	MessageKey  string            `json:"messageKey,omitempty"`
	MessageArgs map[string]string `json:"messageArgs,omitempty"`
	Evidence    []Evidence        `json:"evidence,omitempty"`
	Fix         []Action          `json:"fix,omitempty"`
	References  []string          `json:"references,omitempty"`
}

// Evidence provides structured data supporting a violation finding.
type Evidence struct {
	Type    EvidenceType   `json:"type"`
	Subject string         `json:"subject"`
	Detail  string         `json:"detail"`
	Raw     map[string]any `json:"raw,omitempty"`
}

// Action suggests a step to remediate a violation or proceed.
type Action struct {
	Title      string            `json:"title"`
	TitleKey   string            `json:"titleKey,omitempty"`
	TitleArgs  map[string]string `json:"titleArgs,omitempty"`
	Detail     string            `json:"detail"`
	DetailKey  string            `json:"detailKey,omitempty"`
	DetailArgs map[string]string `json:"detailArgs,omitempty"`
	Patch      PatchSuggestion   `json:"patch,omitempty"`
}

// PatchSuggestion provides a machine-readable fix.
type PatchSuggestion struct {
	Format  string `json:"format"`
	Content string `json:"content"`
}
