package casestore

import (
	"context"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func sampleAcquisition(caseID, evidenceID string) domain.EvidenceAcquisitionRecord {
	return domain.EvidenceAcquisitionRecord{
		SchemaName:       domain.SchemaEvidenceAcquisitionRecord,
		SchemaVersion:    domain.SchemaVersion,
		AcquisitionID:    "acq-111111111111111111111111",
		CaseID:           caseID,
		RequestID:        "acqreq-222222222222222222222222",
		SourceCommitID:   "commit-111111111111111111111111",
		ProducerType:     domain.ProducerTargetResolver,
		ProducerID:       "effexor-recovery-target-resolver",
		ProducerVersion:  "1.0.0",
		ActorType:        domain.ActorSystem,
		AcquiredAt:       "2026-07-27T12:10:00Z",
		TargetIDs:        []string{"target-disk-nvme0n1"},
		InputEvidenceIDs: []string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
		AddedTargetIDs:   []string{},
		AddedEvidenceIDs: []string{evidenceID},
		ParametersSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ResultSHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Limitations:      []string{},
	}
}

func sampleAddedEvidence(caseID, evidenceID, targetID string) domain.EvidenceBundle {
	return domain.EvidenceBundle{
		SchemaName:       domain.SchemaEvidenceBundle,
		SchemaVersion:    domain.SchemaVersion,
		EvidenceID:       evidenceID,
		CaseID:           caseID,
		TargetID:         targetID,
		Collector:        "effexor-recovery-target-resolver",
		CollectorVersion: "1.0.0",
		CapturedAt:       "2026-07-27T12:10:00Z",
		SourceStatus:     "ok",
		FactsSchema:      "windows-boot-topology",
		Facts:            []byte(`{"schema_name":"windows-boot-topology"}`),
		Artifacts:        []domain.ArtifactRef{},
		Limitations:      []string{},
	}
}

func TestPR17SnapshotWithoutAcquisitionsRemainsValid(t *testing.T) {
	t.Parallel()
	if err := enrichedSnapshot(t).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNewEvidenceWithoutAcquisitionRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	added := sampleAddedEvidence(snap.Case.CaseID, "evidence-cccccccccccccccccccccccc", snap.Targets[0].TargetID)
	snap.EvidenceBundles = append(snap.EvidenceBundles, added)
	if err := snap.Validate(); err == nil {
		t.Fatal("expected unaquired evidence rejection")
	}
}

func TestAcquisitionCoversNewEvidence(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	addedID := "evidence-cccccccccccccccccccccccc"
	snap.EvidenceBundles = append(snap.EvidenceBundles, sampleAddedEvidence(snap.Case.CaseID, addedID, snap.Targets[0].TargetID))
	snap.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{sampleAcquisition(snap.Case.CaseID, addedID)}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestInitialEventUnchangedAfterAcquisition(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	initialRefs := append([]string(nil), snap.CoordinatorEvents[0].ReferencedDocumentIDs...)
	addedID := "evidence-cccccccccccccccccccccccc"
	snap.EvidenceBundles = append(snap.EvidenceBundles, sampleAddedEvidence(snap.Case.CaseID, addedID, snap.Targets[0].TargetID))
	snap.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{sampleAcquisition(snap.Case.CaseID, addedID)}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
	got := snap.CoordinatorEvents[0].ReferencedDocumentIDs
	if len(got) != len(initialRefs) {
		t.Fatalf("revision-1 refs changed: %v vs %v", got, initialRefs)
	}
	for i := range got {
		if got[i] != initialRefs[i] {
			t.Fatalf("revision-1 refs changed: %v vs %v", got, initialRefs)
		}
	}
}

func TestDuplicateAddedEvidenceAcrossAcquisitionsRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	addedID := "evidence-cccccccccccccccccccccccc"
	snap.EvidenceBundles = append(snap.EvidenceBundles, sampleAddedEvidence(snap.Case.CaseID, addedID, snap.Targets[0].TargetID))
	a1 := sampleAcquisition(snap.Case.CaseID, addedID)
	a2 := sampleAcquisition(snap.Case.CaseID, addedID)
	a2.AcquisitionID = "acq-333333333333333333333333"
	a2.RequestID = "acqreq-444444444444444444444444"
	snap.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{a1, a2}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected duplicate added evidence rejection")
	}
}

func TestInitialIDRepeatedAsAddedRejected(t *testing.T) {
	t.Parallel()
	snap := enrichedSnapshot(t)
	acq := sampleAcquisition(snap.Case.CaseID, snap.EvidenceBundles[0].EvidenceID)
	snap.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{acq}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected initial-as-added rejection")
	}
}

func TestAcquisitionRoundTrip(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	base := enrichedSnapshot(t)
	parent := mustCommit(t, st, base, nil, CommitReasonCaseSnapshot)

	snap := enrichedSnapshot(t)
	addedID := "evidence-cccccccccccccccccccccccc"
	snap.EvidenceBundles = append(snap.EvidenceBundles, sampleAddedEvidence(snap.Case.CaseID, addedID, snap.Targets[0].TargetID))
	acq := sampleAcquisition(snap.Case.CaseID, addedID)
	acq.SourceCommitID = parent.CommitID
	snap.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{acq}
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	loaded, got, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitID != info.CommitID {
		t.Fatalf("commit mismatch")
	}
	if len(loaded.EvidenceAcquisitions) != 1 {
		t.Fatalf("acquisitions: %+v", loaded.EvidenceAcquisitions)
	}
	if loaded.WorkflowState.Revision != 1 {
		t.Fatalf("workflow revision changed: %d", loaded.WorkflowState.Revision)
	}
	if loaded.Case.CurrentState != domain.CaseStateSnapshotted {
		t.Fatalf("case state changed: %s", loaded.Case.CurrentState)
	}
}

func TestAcquisitionDanglingSourceCommitRejected(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	base := enrichedSnapshot(t)
	parent := mustCommit(t, st, base, nil, CommitReasonCaseSnapshot)

	snap := enrichedSnapshot(t)
	addedID := "evidence-cccccccccccccccccccccccc"
	snap.EvidenceBundles = append(snap.EvidenceBundles, sampleAddedEvidence(snap.Case.CaseID, addedID, snap.Targets[0].TargetID))
	acq := sampleAcquisition(snap.Case.CaseID, addedID)
	acq.SourceCommitID = "commit-dddddddddddddddddddddddd"
	snap.EvidenceAcquisitions = []domain.EvidenceAcquisitionRecord{acq}
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot:          snap,
		Reason:            CommitReasonCaseSnapshot,
		ParentExpectation: ExpectParentCommit(parent.CommitID),
	})
	if err == nil {
		t.Fatal("expected dangling source_commit_id rejection")
	}
}
