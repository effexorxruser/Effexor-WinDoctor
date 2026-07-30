package casestore

import (
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestWorkflowRevisionOrderingIndependentOfOccurredAt(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	// Second analysis-style transition with earlier lexicographic event_id and
	// identical occurred_at must still order by workflow_revision.
	snap.Case.CurrentState = domain.CaseStateDiagnosed
	snap.WorkflowState = &domain.CaseWorkflowState{
		SchemaName:       domain.SchemaCaseWorkflowState,
		SchemaVersion:    domain.SchemaVersion,
		CaseID:           snap.Case.CaseID,
		State:            domain.WorkflowAnalyzed,
		Revision:         2,
		UpdatedAt:        "2026-07-27T12:05:00Z",
		LastTransitionID: "cevt-000000000000000000000002",
	}
	snap.CoordinatorEvents = []domain.CoordinatorEvent{
		{
			SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
			EventID: "cevt-ffffffffffffffffffffffff", CaseID: snap.Case.CaseID,
			EventType: domain.EventCaseCreated, ActorType: domain.ActorSystem,
			OccurredAt: "2026-07-27T12:05:00Z", PreviousState: string(domain.WorkflowCreated),
			NextState: string(domain.WorkflowEvidenceCollected), WorkflowRevision: 1,
			ReferencedDocumentIDs: []string{
				snap.Case.CaseID,
				snap.Targets[0].TargetID,
				snap.EvidenceBundles[0].EvidenceID,
				domain.DocumentIDCaseWorkflowState,
			},
			ReasonCode: "legacy_import_committed",
		},
		{
			SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
			EventID: "cevt-000000000000000000000002", CaseID: snap.Case.CaseID,
			EventType: domain.EventAnalysisCommitted, ActorType: domain.ActorDeterministicAnalyzer,
			OccurredAt: "2026-07-27T12:05:00Z", PreviousState: string(domain.WorkflowEvidenceCollected),
			NextState: string(domain.WorkflowAnalyzed), WorkflowRevision: 2,
			ExpectedCommitID: "commit-111111111111111111111111",
			ReferencedDocumentIDs: []string{
				snap.Case.CaseID,
				"finding-cccccccccccccccccccccccc",
				"evidence-bbbbbbbbbbbbbbbbbbbbbbbb",
				"target-disk-nvme0n1",
				domain.DocumentIDCaseWorkflowState,
			},
			ReasonCode: "analysis_committed",
		},
	}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowRevisionDuplicateRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.WorkflowState.Revision = 2
	snap.Case.CurrentState = domain.CaseStateDiagnosed
	snap.WorkflowState.State = domain.WorkflowAnalyzed
	snap.WorkflowState.LastTransitionID = "cevt-222222222222222222222222"
	ev2 := sampleCoordinatorEvent()
	ev2.EventID = "cevt-222222222222222222222222"
	ev2.EventType = domain.EventAnalysisCommitted
	ev2.PreviousState = string(domain.WorkflowEvidenceCollected)
	ev2.NextState = string(domain.WorkflowAnalyzed)
	ev2.WorkflowRevision = 1 // duplicate
	ev2.ReferencedDocumentIDs = []string{snap.Case.CaseID, "finding-cccccccccccccccccccccccc", domain.DocumentIDCaseWorkflowState}
	ev2.ReasonCode = "analysis_committed"
	snap.CoordinatorEvents = append(snap.CoordinatorEvents, ev2)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected duplicate revision rejection")
	}
}

func TestWorkflowRevisionSkippedRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.WorkflowState.Revision = 2
	snap.Case.CurrentState = domain.CaseStateDiagnosed
	snap.WorkflowState.State = domain.WorkflowAnalyzed
	snap.WorkflowState.LastTransitionID = "cevt-222222222222222222222222"
	ev2 := sampleCoordinatorEvent()
	ev2.EventID = "cevt-222222222222222222222222"
	ev2.EventType = domain.EventAnalysisCommitted
	ev2.PreviousState = string(domain.WorkflowEvidenceCollected)
	ev2.NextState = string(domain.WorkflowAnalyzed)
	ev2.WorkflowRevision = 3 // skipped 2
	ev2.ReferencedDocumentIDs = []string{snap.Case.CaseID, "finding-cccccccccccccccccccccccc", domain.DocumentIDCaseWorkflowState}
	ev2.ReasonCode = "analysis_committed"
	snap.CoordinatorEvents = append(snap.CoordinatorEvents, ev2)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected skipped revision rejection")
	}
}

func TestWorkflowRevisionZeroRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.CoordinatorEvents[0].WorkflowRevision = 0
	if err := snap.Validate(); err == nil {
		t.Fatal("expected revision 0 rejection")
	}
}

func TestLastTransitionNotMaxRevisionRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.WorkflowState.Revision = 2
	snap.Case.CurrentState = domain.CaseStateDiagnosed
	snap.WorkflowState.State = domain.WorkflowAnalyzed
	// Keep last_transition_id pointing at revision 1 event.
	ev2 := sampleCoordinatorEvent()
	ev2.EventID = "cevt-222222222222222222222222"
	ev2.EventType = domain.EventAnalysisCommitted
	ev2.PreviousState = string(domain.WorkflowEvidenceCollected)
	ev2.NextState = string(domain.WorkflowAnalyzed)
	ev2.WorkflowRevision = 2
	ev2.ReferencedDocumentIDs = []string{snap.Case.CaseID, "finding-cccccccccccccccccccccccc", domain.DocumentIDCaseWorkflowState}
	ev2.ReasonCode = "analysis_committed"
	snap.CoordinatorEvents = append(snap.CoordinatorEvents, ev2)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected last_transition_id not-max rejection")
	}
}

func TestWorkflowRevisionDisconnectedChainRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.WorkflowState.Revision = 2
	snap.Case.CurrentState = domain.CaseStateDiagnosed
	snap.WorkflowState.State = domain.WorkflowAnalyzed
	snap.WorkflowState.LastTransitionID = "cevt-222222222222222222222222"
	ev2 := sampleCoordinatorEvent()
	ev2.EventID = "cevt-222222222222222222222222"
	ev2.EventType = domain.EventAnalysisCommitted
	ev2.PreviousState = string(domain.WorkflowPlanProposed)
	ev2.NextState = string(domain.WorkflowAnalyzed)
	ev2.WorkflowRevision = 2
	ev2.ExpectedCommitID = "commit-111111111111111111111111"
	ev2.ReferencedDocumentIDs = []string{snap.Case.CaseID, "finding-cccccccccccccccccccccccc", domain.DocumentIDCaseWorkflowState}
	ev2.ReasonCode = "analysis_committed"
	snap.CoordinatorEvents = append(snap.CoordinatorEvents, ev2)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected disconnected chain rejection")
	}
}

func TestWorkflowRevisionInvalidFirstEventRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	snap.CoordinatorEvents[0].EventType = domain.EventAnalysisCommitted
	snap.CoordinatorEvents[0].PreviousState = string(domain.WorkflowEvidenceCollected)
	snap.CoordinatorEvents[0].NextState = string(domain.WorkflowAnalyzed)
	snap.CoordinatorEvents[0].ExpectedCommitID = "commit-111111111111111111111111"
	if err := snap.Validate(); err == nil {
		t.Fatal("expected invalid first event rejection")
	}
}
