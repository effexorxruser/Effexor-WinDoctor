package domain

import "fmt"

// ActorType classifies who initiated a coordinator transition.
type ActorType string

const (
	ActorSystem                ActorType = "system"
	ActorTechnician            ActorType = "technician"
	ActorDeterministicAnalyzer ActorType = "deterministic_analyzer"
	ActorLLMAdvisor            ActorType = "llm_advisor"
	ActorPolicy                ActorType = "policy"
	ActorExecutor              ActorType = "executor"
	ActorVerifier              ActorType = "verifier"
)

var actorTypes = map[string]struct{}{
	string(ActorSystem): {}, string(ActorTechnician): {}, string(ActorDeterministicAnalyzer): {},
	string(ActorLLMAdvisor): {}, string(ActorPolicy): {}, string(ActorExecutor): {}, string(ActorVerifier): {},
}

// CoordinatorEventType classifies immutable coordinator audit events for PR #17.
type CoordinatorEventType string

const (
	EventCaseCreated       CoordinatorEventType = "case_created"
	EventCaseLoaded        CoordinatorEventType = "case_loaded"
	EventEvidenceCommitted CoordinatorEventType = "evidence_committed"
	EventAnalysisCommitted CoordinatorEventType = "analysis_committed"
	EventPlanCommitted     CoordinatorEventType = "plan_committed"
	EventCaseFailed        CoordinatorEventType = "case_failed"
	EventCaseCancelled     CoordinatorEventType = "case_cancelled"
	EventLegacyCaseAdopted CoordinatorEventType = "legacy_case_adopted"
)

var coordinatorEventTypes = map[string]struct{}{
	string(EventCaseCreated): {}, string(EventCaseLoaded): {}, string(EventEvidenceCommitted): {},
	string(EventAnalysisCommitted): {}, string(EventPlanCommitted): {},
	string(EventCaseFailed): {}, string(EventCaseCancelled): {},
	string(EventLegacyCaseAdopted): {},
}

// DocumentIDCaseWorkflowState is the typed singleton identifier for the
// case-workflow-state document when referenced from coordinator-event
// referenced_document_ids.
const DocumentIDCaseWorkflowState = "case-workflow-state"

// CoordinatorEvent is an immutable audit record stored inside a Case snapshot.
//
// Authoritative resulting snapshot/commit IDs live on Case Store CommitInfo /
// commit-record, not on this event. Those identifiers cannot be embedded in the
// event that participates in computing them (circular dependency).
type CoordinatorEvent struct {
	SchemaName            string               `json:"schema_name"`
	SchemaVersion         string               `json:"schema_version"`
	EventID               string               `json:"event_id"`
	CaseID                string               `json:"case_id"`
	EventType             CoordinatorEventType `json:"event_type"`
	ActorType             ActorType            `json:"actor_type"`
	OccurredAt            string               `json:"occurred_at"`
	PreviousState         string               `json:"previous_state,omitempty"`
	NextState             string               `json:"next_state,omitempty"`
	ExpectedCommitID      string               `json:"expected_commit_id,omitempty"`
	WorkflowRevision      uint64               `json:"workflow_revision,omitempty"`
	ReferencedDocumentIDs []string             `json:"referenced_document_ids"`
	ReasonCode            string               `json:"reason_code"`
	CommandID             string               `json:"command_id,omitempty"`
}

func (e CoordinatorEvent) Validate() error {
	if err := requireSchema(e.SchemaName, e.SchemaVersion, SchemaCoordinatorEvent); err != nil {
		return err
	}
	if err := requireMatch("event_id", e.EventID, reCoordinatorEventID); err != nil {
		return err
	}
	if err := requireMatch("case_id", e.CaseID, reCaseID); err != nil {
		return err
	}
	if err := requireEnum("event_type", string(e.EventType), coordinatorEventTypes); err != nil {
		return err
	}
	if err := requireEnum("actor_type", string(e.ActorType), actorTypes); err != nil {
		return err
	}
	if err := requireRFC3339("occurred_at", e.OccurredAt); err != nil {
		return err
	}
	if e.PreviousState != "" {
		if err := requireEnum("previous_state", e.PreviousState, workflowStates); err != nil {
			return err
		}
	}
	if e.NextState != "" {
		if err := requireEnum("next_state", e.NextState, workflowStates); err != nil {
			return err
		}
	}
	if e.ExpectedCommitID != "" {
		if err := requireMatch("expected_commit_id", e.ExpectedCommitID, reCommitID); err != nil {
			return err
		}
	}
	if IsStateChangingCoordinatorEventType(e.EventType) {
		if e.WorkflowRevision == 0 {
			return fmt.Errorf("workflow_revision is required and must be >= 1 for state-changing event %q", e.EventType)
		}
	} else if e.WorkflowRevision != 0 {
		return fmt.Errorf("workflow_revision must be absent for non-state-changing event %q", e.EventType)
	}
	if e.ReferencedDocumentIDs == nil {
		return fmt.Errorf("referenced_document_ids is required")
	}
	if err := requireMatch("reason_code", e.ReasonCode, reReasonCode); err != nil {
		return err
	}
	if e.CommandID != "" {
		if err := requireMatch("command_id", e.CommandID, reCommandID); err != nil {
			return err
		}
	}
	return nil
}
