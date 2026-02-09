package decision

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidID       = errors.New("decision ID is required")
	ErrInvalidResource = errors.New("resource Kind, Name, and Namespace are required")
	ErrInvalidStatus   = errors.New("invalid decision status")
	ErrInvalidVersion  = errors.New("schema version is required")
)

// Validate checks if the SecurityDecision meets the minimum required fields.
func (d SecurityDecision) Validate() error {
	if d.ID == "" {
		return ErrInvalidID
	}

	if d.Resource.Kind == "" || d.Resource.Name == "" || d.Resource.Namespace == "" {
		return ErrInvalidResource
	}

	if !d.Status.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidStatus, d.Status)
	}

	if d.Version == "" {
		return ErrInvalidVersion
	}

	return nil
}

// IsValid checks if the DecisionStatus is one of the allowed constants.
func (s DecisionStatus) IsValid() bool {
	switch s {
	case StatusBlocked, StatusAllowed:
		return true
	default:
		return false
	}
}
