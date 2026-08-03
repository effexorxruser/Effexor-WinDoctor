package domain

import (
	"fmt"
	"time"
)

// RepairApproval is an explicit technician binding to an immutable plan digest.
// It does not authorize immediate execution without future backup/executor gates.
type RepairApproval struct {
	SchemaName        string   `json:"schema_name"`
	SchemaVersion     string   `json:"schema_version"`
	ApprovalID        string   `json:"approval_id"`
	CaseID            string   `json:"case_id"`
	RequestID         string   `json:"request_id"`
	PlanID            string   `json:"plan_id"`
	PlanDigest        string   `json:"plan_digest"`
	EvaluationID      string   `json:"evaluation_id"`
	PolicyDigest      string   `json:"policy_digest"`
	SourceCommitID    string   `json:"source_commit_id"`
	TopologyID        string   `json:"topology_id,omitempty"`
	TechnicianRef     string   `json:"technician_ref"`
	ApprovedAt        string   `json:"approved_at"`
	Status            string   `json:"status"`
	AcknowledgedRisks []string `json:"acknowledged_risks"`
	ScopeSummary      string   `json:"scope_summary"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	Limitations       []string `json:"limitations"`
}

var approvalStatuses = map[string]struct{}{
	"approved": {},
	"rejected": {},
}

func (a RepairApproval) Validate() error {
	if err := requireSchema(a.SchemaName, a.SchemaVersion, SchemaRepairApproval); err != nil {
		return err
	}
	if err := requireMatch("approval_id", a.ApprovalID, reRepairApprovalID); err != nil {
		return err
	}
	if err := requireMatch("case_id", a.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireMatch("request_id", a.RequestID, reApprovalRequestID); err != nil {
		return err
	}
	if err := requireMatch("plan_id", a.PlanID, rePlanID); err != nil {
		return err
	}
	if err := requireSHA256("plan_digest", a.PlanDigest); err != nil {
		return err
	}
	if err := requireMatch("evaluation_id", a.EvaluationID, rePolicyEvaluationID); err != nil {
		return err
	}
	if err := requireSHA256("policy_digest", a.PolicyDigest); err != nil {
		return err
	}
	if err := requireMatch("source_commit_id", a.SourceCommitID, reCommitID); err != nil {
		return err
	}
	if a.TopologyID != "" {
		if err := requireMatch("topology_id", a.TopologyID, reTopologyID); err != nil {
			return err
		}
	}
	if err := requireMatch("technician_ref", a.TechnicianRef, reTechnicianRef); err != nil {
		return err
	}
	if err := requireRFC3339("approved_at", a.ApprovedAt); err != nil {
		return err
	}
	if err := requireEnum("status", a.Status, approvalStatuses); err != nil {
		return err
	}
	if len(a.AcknowledgedRisks) == 0 || len(a.AcknowledgedRisks) > 32 {
		return fmt.Errorf("acknowledged_risks must contain between 1 and 32 entries")
	}
	if err := requireNonEmpty("scope_summary", a.ScopeSummary); err != nil {
		return err
	}
	if a.ExpiresAt != "" {
		if err := requireRFC3339("expires_at", a.ExpiresAt); err != nil {
			return err
		}
		approved, err := time.Parse(time.RFC3339, a.ApprovedAt)
		if err != nil {
			return fmt.Errorf("approved_at: %w", err)
		}
		expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
		if err != nil {
			return fmt.Errorf("expires_at: %w", err)
		}
		if !expires.After(approved) {
			return fmt.Errorf("expires_at must be after approved_at")
		}
	}
	if len(a.Limitations) == 0 || len(a.Limitations) > 32 {
		return fmt.Errorf("limitations must contain between 1 and 32 entries")
	}
	return nil
}

// ValidateRepairApprovalRefs checks case/plan/policy refs.
func (a RepairApproval) ValidateRepairApprovalRefs(refs CrossRefs) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := requireRef("case_id", a.CaseID, refs.CaseIDs); err != nil {
		return err
	}
	if err := requireRef("plan_id", a.PlanID, refs.PlanIDs); err != nil {
		return err
	}
	if refs.PolicyEvaluationIDs != nil {
		if err := requireRef("evaluation_id", a.EvaluationID, refs.PolicyEvaluationIDs); err != nil {
			return err
		}
	}
	return nil
}
