package domain

import "fmt"

// CaseStateForWorkflow maps coordinator WorkflowStateName onto the existing
// CaseManifest.current_state enum without widening case-manifest 1.0.0.
//
// Mapping (PR #17):
//
//	created            → NEW          (pre-commit conceptual state; rarely persisted alone)
//	evidence_collected → SNAPSHOTTED
//	analyzed           → DIAGNOSED
//	plan_proposed      → PLANNED
//	failed             → FAILED
//	cancelled          → CANCELLED
//
// Later workflow states are reserved for future PRs and map to the closest
// existing CaseState when Coordinator begins using them.
func CaseStateForWorkflow(state WorkflowStateName) (CaseState, error) {
	switch state {
	case WorkflowCreated:
		return CaseStateNew, nil
	case WorkflowEvidenceCollected:
		return CaseStateSnapshotted, nil
	case WorkflowAnalyzed:
		return CaseStateDiagnosed, nil
	case WorkflowPlanProposed:
		return CaseStatePlanned, nil
	case WorkflowAwaitingApproval:
		return CaseStateAwaitingApproval, nil
	case WorkflowApproved:
		return CaseStatePlanned, nil // approval recorded separately in later PRs
	case WorkflowBackingUp, WorkflowReadyToExecute:
		return CaseStatePlanned, nil
	case WorkflowExecuting:
		return CaseStateExecuting, nil
	case WorkflowVerifying:
		return CaseStateVerifying, nil
	case WorkflowCompleted:
		return CaseStateResolved, nil
	case WorkflowFailed:
		return CaseStateFailed, nil
	case WorkflowRollbackRequired:
		return CaseStateRollbackRequired, nil
	case WorkflowRollingBack:
		return CaseStateRollbackRequired, nil
	case WorkflowRolledBack:
		return CaseStateRolledBack, nil
	case WorkflowCancelled:
		return CaseStateCancelled, nil
	default:
		return "", fmt.Errorf("unknown workflow state %q", state)
	}
}

// CompatibleWorkflowAndCaseState reports whether the pair is an allowed
// WorkflowState ↔ CaseManifest.CurrentState pairing for PR #17.
func CompatibleWorkflowAndCaseState(workflow WorkflowStateName, caseState CaseState) bool {
	want, err := CaseStateForWorkflow(workflow)
	if err != nil {
		return false
	}
	return want == caseState
}
