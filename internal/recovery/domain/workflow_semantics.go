package domain

import "fmt"

// ValidatePR17WorkflowStateDocumentSemantics validates PR #17 single-document
// workflow-state rules that do not depend on cross-document references.
func ValidatePR17WorkflowStateDocumentSemantics(workflow CaseWorkflowState) error {
	switch workflow.State {
	case WorkflowEvidenceCollected, WorkflowAnalyzed:
		if workflow.ActivePlanID != "" {
			return fmt.Errorf("state %q must not set active_plan_id", workflow.State)
		}
		if workflow.ActiveExecutionID != "" {
			return fmt.Errorf("state %q must not set active_execution_id", workflow.State)
		}
		if workflow.Failure != nil {
			return fmt.Errorf("state %q must not set failure", workflow.State)
		}
	case WorkflowPlanProposed, WorkflowAwaitingApproval, WorkflowApproved:
		if workflow.ActivePlanID == "" {
			return fmt.Errorf("state %q requires active_plan_id", workflow.State)
		}
		if workflow.ActiveExecutionID != "" {
			return fmt.Errorf("state %q must not set active_execution_id", workflow.State)
		}
		if workflow.Failure != nil {
			return fmt.Errorf("state %q must not set failure", workflow.State)
		}
	case WorkflowFailed:
		if workflow.Failure == nil {
			return fmt.Errorf("state %q requires failure", workflow.State)
		}
		if workflow.ActiveExecutionID != "" {
			return fmt.Errorf("state %q must not set active_execution_id", workflow.State)
		}
	case WorkflowCancelled:
		if workflow.Failure != nil {
			return fmt.Errorf("state %q must not set failure", workflow.State)
		}
		if workflow.ActiveExecutionID != "" {
			return fmt.Errorf("state %q must not set active_execution_id", workflow.State)
		}
	}
	return nil
}

// ValidatePR17WorkflowStateSemantics validates persisted PR #17 workflow-state
// semantics that depend on the latest workflow document, case-manifest, and
// last transition event.
func ValidatePR17WorkflowStateSemantics(workflow CaseWorkflowState, caseManifest CaseManifest, lastEvent CoordinatorEvent) error {
	if err := ValidatePR17WorkflowStateDocumentSemantics(workflow); err != nil {
		return err
	}
	if workflow.State == WorkflowCreated {
		return fmt.Errorf("persisted workflow state %q is not implemented in PR #17", workflow.State)
	}
	switch workflow.State {
	case WorkflowEvidenceCollected, WorkflowAnalyzed:
	case WorkflowPlanProposed:
		if lastEvent.EventType != EventPlanCommitted {
			return fmt.Errorf("state %q requires last event %q", workflow.State, EventPlanCommitted)
		}
		if !containsString(lastEvent.ReferencedDocumentIDs, workflow.ActivePlanID) {
			return fmt.Errorf("state %q requires last event refs to contain active_plan_id", workflow.State)
		}
	case WorkflowAwaitingApproval:
		if lastEvent.EventType != EventPolicyEvaluated {
			return fmt.Errorf("state %q requires last event %q", workflow.State, EventPolicyEvaluated)
		}
		if !containsString(lastEvent.ReferencedDocumentIDs, workflow.ActivePlanID) {
			return fmt.Errorf("state %q requires last event refs to contain active_plan_id", workflow.State)
		}
	case WorkflowApproved:
		if lastEvent.EventType != EventApprovalCommitted {
			return fmt.Errorf("state %q requires last event %q", workflow.State, EventApprovalCommitted)
		}
		if !containsString(lastEvent.ReferencedDocumentIDs, workflow.ActivePlanID) {
			return fmt.Errorf("state %q requires last event refs to contain active_plan_id", workflow.State)
		}
	case WorkflowFailed:
	case WorkflowCancelled:
	default:
		return fmt.Errorf("persisted workflow state %q is not implemented in PR #17", workflow.State)
	}
	if workflow.UpdatedAt != caseManifest.UpdatedAt {
		return fmt.Errorf("workflow updated_at %q must equal case updated_at %q", workflow.UpdatedAt, caseManifest.UpdatedAt)
	}
	if lastEvent.OccurredAt != workflow.UpdatedAt {
		return fmt.Errorf("last transition occurred_at %q must equal workflow updated_at %q", lastEvent.OccurredAt, workflow.UpdatedAt)
	}
	if lastEvent.NextState != string(workflow.State) {
		return fmt.Errorf("last transition next_state %q must equal workflow state %q", lastEvent.NextState, workflow.State)
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
