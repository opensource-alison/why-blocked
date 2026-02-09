package decision

import (
	"errors"
	"testing"
	"time"
)

func TestSecurityDecision_Validate(t *testing.T) {
	validDecision := SecurityDecision{
		ID:        "test-123",
		Timestamp: time.Now(),
		Version:   "v1alpha1",
		Status:    StatusBlocked,
		Resource: ResourceRef{
			Kind:      "Deployment",
			Name:      "test-app",
			Namespace: "default",
		},
	}

	tests := []struct {
		name    string
		modify  func(*SecurityDecision)
		wantErr error
	}{
		{
			name:    "valid decision",
			modify:  func(d *SecurityDecision) {},
			wantErr: nil,
		},
		{
			name: "missing ID",
			modify: func(d *SecurityDecision) {
				d.ID = ""
			},
			wantErr: ErrInvalidID,
		},
		{
			name: "missing resource kind",
			modify: func(d *SecurityDecision) {
				d.Resource.Kind = ""
			},
			wantErr: ErrInvalidResource,
		},
		{
			name: "missing resource name",
			modify: func(d *SecurityDecision) {
				d.Resource.Name = ""
			},
			wantErr: ErrInvalidResource,
		},
		{
			name: "missing resource namespace",
			modify: func(d *SecurityDecision) {
				d.Resource.Namespace = ""
			},
			wantErr: ErrInvalidResource,
		},
		{
			name: "invalid status",
			modify: func(d *SecurityDecision) {
				d.Status = "INVALID"
			},
			wantErr: ErrInvalidStatus,
		},
		{
			name: "missing version",
			modify: func(d *SecurityDecision) {
				d.Version = ""
			},
			wantErr: ErrInvalidVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := validDecision
			tt.modify(&d)
			err := d.Validate()

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Validate() error = %v, wantErr nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() error = nil, wantErr %v", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestDecisionStatus_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		status DecisionStatus
		want   bool
	}{
		{
			name:   "BLOCKED is valid",
			status: StatusBlocked,
			want:   true,
		},
		{
			name:   "ALLOWED is valid",
			status: StatusAllowed,
			want:   true,
		},
		{
			name:   "empty string is invalid",
			status: "",
			want:   false,
		},
		{
			name:   "random string is invalid",
			status: "PENDING",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
