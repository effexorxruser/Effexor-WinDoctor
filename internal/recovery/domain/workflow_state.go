package domain

import "fmt"

// WorkflowStateName is the coordinator-owned case lifecycle state.
// This is distinct from CaseManifest.current_state (legacy CaseState enum).
type WorkflowStateName string

const (
	WorkflowCreated           WorkflowStateName = "created"
	WorkflowEvidenceCollected WorkflowStateName = "evidence_collected"
	WorkflowAnalyzed          WorkflowStateName = "analyzed"
	WorkflowPlanProposed      WorkflowStateName = "plan_proposed"
	WorkflowAwaitingApproval  WorkflowStateName = "awaiting_approval"
	WorkflowApproved          WorkflowStateName = "approved"
	WorkflowBackingUp         WorkflowStateName = "backing_up"
	WorkflowReadyToExecute    WorkflowStateName = "ready_to_execute"
	WorkflowExecuting         WorkflowStateName = "executing"
	WorkflowVerifying         WorkflowStateName = "verifying"
	WorkflowCompleted         WorkflowStateName = "completed"
	WorkflowFailed            WorkflowStateName = "failed"
	WorkflowRollbackRequired  WorkflowStateName = "rollback_required"
	WorkflowRollingBack       WorkflowStateName = "rolling_back"
	WorkflowRolledBack        WorkflowStateName = "rolled_back"
	WorkflowCancelled         WorkflowStateName = "cancelled"
)

var workflowStates = map[string]struct{}{
	string(WorkflowCreated): {}, string(WorkflowEvidenceCollected): {}, string(WorkflowAnalyzed): {},
	string(WorkflowPlanProposed): {}, string(WorkflowAwaitingApproval): {}, string(WorkflowApproved): {},
	string(WorkflowBackingUp): {}, string(WorkflowReadyToExecute): {}, string(WorkflowExecuting): {},
	string(WorkflowVerifying): {}, string(WorkflowCompleted): {}, string(WorkflowFailed): {},
	string(WorkflowRollbackRequired): {}, string(WorkflowRollingBack): {}, string(WorkflowRolledBack): {},
	string(WorkflowCancelled): {},
}

// WorkflowFailure is an optional structured failure attached to workflow state.
type WorkflowFailure struct {
	ReasonCode string `json:"reason_code"`
	DetailCode string `json:"detail_code,omitempty"`
}

func (f WorkflowFailure) Validate() error {
	if err := requireMatch("reason_code", f.ReasonCode, reReasonCode); err != nil {
		return err
	}
	if f.DetailCode != "" {
		if err := requireMatch("detail_code", f.DetailCode, reReasonCode); err != nil {
			return err
		}
	}
	return nil
}

// CaseWorkflowState is the versioned companion document for coordinator workflow.
type CaseWorkflowState struct {
	SchemaName        string            `json:"schema_name"`
	SchemaVersion     string            `json:"schema_version"`
	CaseID            string            `json:"case_id"`
	State             WorkflowStateName `json:"state"`
	Revision          uint64            `json:"revision"`
	UpdatedAt         string            `json:"updated_at"`
	LastTransitionID  string            `json:"last_transition_id"`
	ActivePlanID      string            `json:"active_plan_id,omitempty"`
	ActiveExecutionID string            `json:"active_execution_id,omitempty"`
	Failure           *WorkflowFailure  `json:"failure,omitempty"`
}

func (w CaseWorkflowState) Validate() error {
	if err := requireSchema(w.SchemaName, w.SchemaVersion, SchemaCaseWorkflowState); err != nil {
		return err
	}
	if err := requireMatch("case_id", w.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireEnum("state", string(w.State), workflowStates); err != nil {
		return err
	}
	if w.Revision < 1 {
		return fmt.Errorf("revision must be >= 1")
	}
	if err := requireRFC3339("updated_at", w.UpdatedAt); err != nil {
		return err
	}
	if err := requireMatch("last_transition_id", w.LastTransitionID, reCoordinatorEventID); err != nil {
		return err
	}
	if w.ActivePlanID != "" {
		if err := requireMatch("active_plan_id", w.ActivePlanID, rePlanID); err != nil {
			return err
		}
	}
	if w.ActiveExecutionID != "" {
		if err := requireMatch("active_execution_id", w.ActiveExecutionID, reExecutionID); err != nil {
			return err
		}
	}
	if w.Failure != nil {
		if err := w.Failure.Validate(); err != nil {
			return fmt.Errorf("failure: %w", err)
		}
	}
	return nil
}
