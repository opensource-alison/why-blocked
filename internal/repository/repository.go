package repository

import (
	"errors"
	"github.com/alisonui/why-blocked/internal/decision"
)

var (
	ErrNotFound    = errors.New("decision not found")
	ErrInvalidData = errors.New("invalid decision data")
)

type DecisionRepository interface {
	Save(decision decision.SecurityDecision) error
	GetByID(id string) (decision.SecurityDecision, error)
	GetLatest(kind, name, namespace string) (decision.SecurityDecision, error)
	List(namespace string, limit int) ([]decision.SecurityDecision, error)
}
