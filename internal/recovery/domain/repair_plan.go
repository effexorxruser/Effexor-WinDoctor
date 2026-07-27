package domain

import "fmt"

// PlanStep is one ordered operation reference inside a RepairPlan.
type PlanStep struct {
	StepID           string   `json:"step_id"`
	OperationID      string   `json:"operation_id"`
	OperationVersion string   `json:"operation_version"`
	TargetID         string   `json:"target_id"`
	DependsOn        []string `json:"depends_on"`
	ApprovalRequired bool     `json:"approval_required"`
	BackupRequired   bool     `json:"backup_required"`
}

func (s PlanStep) Validate() error {
	if err := requireNonEmpty("step_id", s.StepID); err != nil {
		return err
	}
	if err := requireMatch("operation_id", s.OperationID, reOperationID); err != nil {
		return err
	}
	if !reSemver.MatchString(s.OperationVersion) {
		return fmt.Errorf("operation_version must be semver MAJOR.MINOR.PATCH")
	}
	if err := requireMatch("target_id", s.TargetID, reTargetID); err != nil {
		return err
	}
	if s.DependsOn == nil {
		return fmt.Errorf("depends_on is required")
	}
	return nil
}

// RepairPlan is a document-only plan of typed operations. No planner is included.
type RepairPlan struct {
	SchemaName           string     `json:"schema_name"`
	SchemaVersion        string     `json:"schema_version"`
	PlanID               string     `json:"plan_id"`
	CaseID               string     `json:"case_id"`
	FindingRefs          []string   `json:"finding_refs"`
	Steps                []PlanStep `json:"steps"`
	RiskSummary          string     `json:"risk_summary"`
	BackupRequirements   []string   `json:"backup_requirements"`
	ApprovalRequirements []string   `json:"approval_requirements"`
	Status               string     `json:"status"`
}

var planStatuses = map[string]struct{}{
	"draft":             {},
	"ready":             {},
	"awaiting_approval": {},
	"approved":          {},
	"rejected":          {},
	"superseded":        {},
	"cancelled":         {},
}

func (p RepairPlan) Validate() error {
	if err := requireSchema(p.SchemaName, p.SchemaVersion, SchemaRepairPlan); err != nil {
		return err
	}
	if err := requireMatch("plan_id", p.PlanID, rePlanID); err != nil {
		return err
	}
	if err := requireMatch("case_id", p.CaseID, reCaseID); err != nil {
		return err
	}
	if p.FindingRefs == nil {
		return fmt.Errorf("finding_refs is required")
	}
	for i, id := range p.FindingRefs {
		if err := requireMatch(fmt.Sprintf("finding_refs[%d]", i), id, reFindingID); err != nil {
			return err
		}
	}
	if p.Steps == nil {
		return fmt.Errorf("steps is required")
	}
	stepIDs := map[string]struct{}{}
	for i, step := range p.Steps {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("steps[%d]: %w", i, err)
		}
		if _, dup := stepIDs[step.StepID]; dup {
			return fmt.Errorf("duplicate step_id %q", step.StepID)
		}
		stepIDs[step.StepID] = struct{}{}
	}
	for i, step := range p.Steps {
		for _, dep := range step.DependsOn {
			if _, ok := stepIDs[dep]; !ok {
				return fmt.Errorf("steps[%d] depends_on unknown step_id %q", i, dep)
			}
		}
	}
	if err := requireNonEmpty("risk_summary", p.RiskSummary); err != nil {
		return err
	}
	if p.BackupRequirements == nil {
		return fmt.Errorf("backup_requirements is required")
	}
	if p.ApprovalRequirements == nil {
		return fmt.Errorf("approval_requirements is required")
	}
	if err := requireEnum("status", p.Status, planStatuses); err != nil {
		return err
	}
	return nil
}
