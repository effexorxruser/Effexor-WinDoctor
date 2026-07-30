package domain

import "fmt"

func isPR17AllowedActor(actor ActorType) bool {
	switch actor {
	case ActorSystem, ActorTechnician, ActorDeterministicAnalyzer:
		return true
	default:
		return false
	}
}

// IsStateChangingCoordinatorEventType reports whether the event type advances
// WorkflowState.Revision in PR #17. It is pure and safe for concurrent use.
func IsStateChangingCoordinatorEventType(eventType CoordinatorEventType) bool {
	switch eventType {
	case EventCaseCreated, EventLegacyCaseAdopted, EventAnalysisCommitted,
		EventPlanCommitted, EventCaseFailed, EventCaseCancelled:
		return true
	default:
		return false
	}
}

func allowedActorForPR17Event(eventType CoordinatorEventType, actor ActorType) bool {
	switch eventType {
	case EventCaseCreated, EventLegacyCaseAdopted:
		return actor == ActorSystem || actor == ActorTechnician
	case EventAnalysisCommitted:
		return actor == ActorSystem || actor == ActorDeterministicAnalyzer
	case EventPlanCommitted:
		return actor == ActorSystem || actor == ActorTechnician || actor == ActorDeterministicAnalyzer
	case EventCaseFailed, EventCaseCancelled:
		return isPR17AllowedActor(actor)
	default:
		return true
	}
}

func validPR17TransitionForEvent(eventType CoordinatorEventType, prev, next WorkflowStateName) bool {
	switch eventType {
	case EventCaseCreated:
		return prev == WorkflowCreated && next == WorkflowEvidenceCollected
	case EventLegacyCaseAdopted:
		return prev == "" && next == WorkflowEvidenceCollected
	case EventAnalysisCommitted:
		return (prev == WorkflowEvidenceCollected && next == WorkflowAnalyzed) ||
			(prev == WorkflowAnalyzed && next == WorkflowAnalyzed)
	case EventPlanCommitted:
		return prev == WorkflowAnalyzed && next == WorkflowPlanProposed
	case EventCaseFailed:
		return (prev == WorkflowCreated || prev == WorkflowEvidenceCollected || prev == WorkflowAnalyzed || prev == WorkflowPlanProposed) &&
			next == WorkflowFailed
	case EventCaseCancelled:
		return (prev == WorkflowCreated || prev == WorkflowEvidenceCollected || prev == WorkflowAnalyzed || prev == WorkflowPlanProposed) &&
			next == WorkflowCancelled
	default:
		return false
	}
}

// ValidatePR17CoordinatorEventSemantics validates immutable coordinator-event
// semantics shared by Coordinator writers and Case Store readers.
func ValidatePR17CoordinatorEventSemantics(e CoordinatorEvent) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if !IsStateChangingCoordinatorEventType(e.EventType) {
		return nil
	}
	if !isPR17AllowedActor(e.ActorType) {
		return fmt.Errorf("actor_type %q is not permitted in PR #17", e.ActorType)
	}
	if !allowedActorForPR17Event(e.EventType, e.ActorType) {
		return fmt.Errorf("actor_type %q may not emit event_type %q", e.ActorType, e.EventType)
	}
	prev := WorkflowStateName(e.PreviousState)
	next := WorkflowStateName(e.NextState)
	if !validPR17TransitionForEvent(e.EventType, prev, next) {
		return fmt.Errorf("event_type %q has invalid transition %q -> %q", e.EventType, e.PreviousState, e.NextState)
	}
	if e.EventType == EventCaseCreated {
		if e.WorkflowRevision != 1 {
			return fmt.Errorf("case_created must use workflow_revision 1")
		}
		if e.ExpectedCommitID != "" {
			return fmt.Errorf("case_created must not set expected_commit_id")
		}
		return nil
	}
	if e.EventType == EventLegacyCaseAdopted {
		if e.WorkflowRevision != 1 {
			return fmt.Errorf("legacy_case_adopted must use workflow_revision 1")
		}
		if e.ExpectedCommitID == "" {
			return fmt.Errorf("legacy_case_adopted must set expected_commit_id")
		}
		return nil
	}
	if e.WorkflowRevision <= 1 {
		return fmt.Errorf("event_type %q requires workflow_revision > 1", e.EventType)
	}
	if e.ExpectedCommitID == "" {
		return fmt.Errorf("event_type %q requires expected_commit_id", e.EventType)
	}
	return nil
}
