package coordinator

import (
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func validateTransition(from, to domain.WorkflowStateName, actor domain.ActorType, findings int, plans int) error {
	var eventType domain.CoordinatorEventType
	switch {
	case from == domain.WorkflowCreated && to == domain.WorkflowEvidenceCollected:
		eventType = domain.EventCaseCreated
	case from == "" && to == domain.WorkflowEvidenceCollected:
		eventType = domain.EventLegacyCaseAdopted
	case (from == domain.WorkflowEvidenceCollected && to == domain.WorkflowAnalyzed) ||
		(from == domain.WorkflowAnalyzed && to == domain.WorkflowAnalyzed):
		eventType = domain.EventAnalysisCommitted
	case from == domain.WorkflowAnalyzed && to == domain.WorkflowPlanProposed:
		eventType = domain.EventPlanCommitted
	case (from == domain.WorkflowEvidenceCollected || from == domain.WorkflowAnalyzed || from == domain.WorkflowPlanProposed) &&
		to == domain.WorkflowFailed:
		eventType = domain.EventCaseFailed
	case (from == domain.WorkflowEvidenceCollected || from == domain.WorkflowAnalyzed || from == domain.WorkflowPlanProposed) &&
		to == domain.WorkflowCancelled:
		eventType = domain.EventCaseCancelled
	default:
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "not_allowed",
			Message: fmt.Sprintf("transition %s -> %s is not implemented in PR #17", from, to),
		}
	}
	semantics := domain.CoordinatorEvent{
		SchemaName:       domain.SchemaCoordinatorEvent,
		SchemaVersion:    domain.SchemaVersion,
		EventID:          "cevt-111111111111111111111111",
		CaseID:           "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		EventType:        eventType,
		ActorType:        actor,
		OccurredAt:       "2026-07-29T12:00:00Z",
		PreviousState:    string(from),
		NextState:        string(to),
		WorkflowRevision: 2,
		ExpectedCommitID: "commit-111111111111111111111111",
		ReferencedDocumentIDs: []string{
			"case-aaaaaaaaaaaaaaaaaaaaaaaa",
		},
		ReasonCode: "test_reason",
	}
	if eventType == domain.EventCaseCreated {
		semantics.WorkflowRevision = 1
		semantics.ExpectedCommitID = ""
	}
	if eventType == domain.EventLegacyCaseAdopted {
		semantics.WorkflowRevision = 1
		semantics.PreviousState = ""
	}
	if err := domain.ValidatePR17CoordinatorEventSemantics(semantics); err != nil {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "actor_not_allowed",
			Message: err.Error(),
		}
	}
	if eventType == domain.EventAnalysisCommitted && findings == 0 {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "missing_findings",
			Message: "transition requires at least one Finding",
		}
	}
	if eventType == domain.EventPlanCommitted && plans == 0 {
		return &TransitionError{
			From:    string(from),
			To:      string(to),
			Reason:  "missing_plan",
			Message: "transition requires at least one RepairPlan",
		}
	}
	return nil
}
