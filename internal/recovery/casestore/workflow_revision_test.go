package casestore

import (
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestWorkflowRevisionOrderingIndependentOfOccurredAt(t *testing.T) {
	t.Parallel()
	snap := analyzedSnapshot(t)
	// Second analysis-style transition with earlier lexicographic event_id and
	// identical occurred_at must still order by workflow_revision.
	snap.CoordinatorEvents[0].EventID = "cevt-ffffffffffffffffffffffff"
	snap.CoordinatorEvents[0].OccurredAt = "2026-07-27T12:05:00Z"
	snap.CoordinatorEvents[1].EventID = "cevt-000000000000000000000002"
	snap.CoordinatorEvents[1].OccurredAt = "2026-07-27T12:05:00Z"
	snap.Case.UpdatedAt = "2026-07-27T12:05:00Z"
	snap.WorkflowState.UpdatedAt = "2026-07-27T12:05:00Z"
	snap.WorkflowState.LastTransitionID = "cevt-000000000000000000000002"
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowRevisionDuplicateRejected(t *testing.T) {
	t.Parallel()
	snap := analyzedSnapshot(t)
	snap.CoordinatorEvents[1].WorkflowRevision = 1 // duplicate
	if err := snap.Validate(); err == nil {
		t.Fatal("expected duplicate revision rejection")
	}
}

func TestWorkflowRevisionSkippedRejected(t *testing.T) {
	t.Parallel()
	snap := analyzedSnapshot(t)
	snap.CoordinatorEvents[1].WorkflowRevision = 3 // skipped 2
	snap.WorkflowState.Revision = 3
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
	snap := analyzedSnapshot(t)
	// Keep last_transition_id pointing at revision 1 event.
	snap.WorkflowState.LastTransitionID = snap.CoordinatorEvents[0].EventID
	if err := snap.Validate(); err == nil {
		t.Fatal("expected last_transition_id not-max rejection")
	}
}

func TestWorkflowRevisionDisconnectedChainRejected(t *testing.T) {
	t.Parallel()
	snap := analyzedSnapshot(t)
	snap.CoordinatorEvents[1].PreviousState = string(domain.WorkflowPlanProposed)
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
