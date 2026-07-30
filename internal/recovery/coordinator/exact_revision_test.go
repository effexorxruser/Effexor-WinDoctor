package coordinator_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestRandomIDSourceRevisionOrder(t *testing.T) {
	t.Parallel()
	clockAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	st, err := casestore.Open(root, casestore.Options{
		Clock:   fixedClock{t: clockAt},
		Entropy: &cyclicEntropy{pattern: []byte{9, 8, 7, 6, 5, 4, 3, 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
		Clock: fixedClock{t: clockAt},
	})
	if err != nil {
		t.Fatal(err)
	}
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	ev := view.Snapshot.EvidenceBundles[0].EvidenceID
	tg := view.Snapshot.Targets[0].TargetID
	a, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(caseID, ev, tg)},
	})
	if err != nil {
		t.Fatal(err)
	}
	findingB := sampleFinding(caseID, ev, tg)
	findingB.FindingID = "finding-bbbbbbbbbbbbbbbbbbbbbbbb"
	b, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: a.CommitInfo.CommitID,
		Findings: []domain.Finding{findingB},
	})
	if err != nil {
		t.Fatal(err)
	}
	byRev := map[uint64]string{}
	for _, ev := range b.Snapshot.CoordinatorEvents {
		if ev.WorkflowRevision > 0 {
			byRev[ev.WorkflowRevision] = ev.EventID
		}
	}
	if byRev[b.Snapshot.WorkflowState.Revision] != b.Snapshot.WorkflowState.LastTransitionID {
		t.Fatalf("last_transition_id not max revision event")
	}
}

type hookStore struct {
	inner       coordinator.Store
	afterCommit func(casestore.CommitInfo)
}

func (s *hookStore) Commit(ctx context.Context, req casestore.CommitRequest) (casestore.CommitInfo, error) {
	info, err := s.inner.Commit(ctx, req)
	if err == nil && s.afterCommit != nil {
		s.afterCommit(info)
	}
	return info, err
}

func (s *hookStore) LoadLatest(ctx context.Context, caseID string) (casestore.Snapshot, casestore.CommitInfo, error) {
	return s.inner.LoadLatest(ctx, caseID)
}

func (s *hookStore) Verify(ctx context.Context, caseID string) (casestore.IntegrityReport, error) {
	return s.inner.Verify(ctx, caseID)
}

func TestWriteReturnsExactCommittedRevision(t *testing.T) {
	t.Parallel()
	clockAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	st, err := casestore.Open(root, casestore.Options{
		Clock:   fixedClock{t: clockAt},
		Entropy: &cyclicEntropy{pattern: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		viewB coordinator.CaseView
		errB  error
		ranB  bool
	)
	hs := &hookStore{inner: st}
	coordA, err := coordinator.New(hs, coordinator.DefaultImporter{}, coordinator.Options{
		Clock: fixedClock{t: clockAt},
		IDs:   &seqIDs{},
	})
	if err != nil {
		t.Fatal(err)
	}
	coordB, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
		Clock: fixedClock{t: clockAt},
		IDs:   &seqIDs{n: 100},
	})
	if err != nil {
		t.Fatal(err)
	}

	created, err := coordA.CreateCase(context.Background(), coordinator.CreateCaseRequest{
		DiagnosticReport: reportFixture(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	createCommitID := created.CommitInfo.CommitID
	caseID := created.Snapshot.Case.CaseID
	evID := created.Snapshot.EvidenceBundles[0].EvidenceID
	tg := created.Snapshot.Targets[0].TargetID
	findingA := sampleFinding(caseID, evID, tg)
	findingB := sampleFinding(caseID, evID, tg)
	findingB.FindingID = "finding-bbbbbbbbbbbbbbbbbbbbbbbb"

	hs.afterCommit = func(info casestore.CommitInfo) {
		mu.Lock()
		defer mu.Unlock()
		if ranB || info.CommitID == createCommitID {
			return
		}
		ranB = true
		viewB, errB = coordB.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
			CaseID: caseID, ExpectedCommitID: info.CommitID,
			Findings: []domain.Finding{findingB},
		})
	}

	viewA, err := coordA.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: createCommitID,
		Findings: []domain.Finding{findingA},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if errB != nil {
		t.Fatalf("writer B: %v", errB)
	}
	if !ranB {
		t.Fatal("writer B did not run")
	}
	if viewA.CommitInfo.CommitID == viewB.CommitInfo.CommitID {
		t.Fatal("writers returned the same commit")
	}
	if viewA.Snapshot.WorkflowState.Revision != 2 {
		t.Fatalf("writer A revision=%d want 2", viewA.Snapshot.WorkflowState.Revision)
	}
	if viewB.Snapshot.WorkflowState.Revision != 3 {
		t.Fatalf("writer B revision=%d want 3", viewB.Snapshot.WorkflowState.Revision)
	}
	if len(viewA.Snapshot.Findings) != 1 || viewA.Snapshot.Findings[0].FindingID != findingA.FindingID {
		t.Fatal("writer A must return exact commit A snapshot")
	}
	if len(viewB.Snapshot.Findings) != 2 {
		t.Fatal("writer B must see both findings")
	}
	latest, _, err := st.LoadLatest(context.Background(), caseID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.WorkflowState.Revision != 3 {
		t.Fatal("latest head should be B")
	}
}

func TestAdoptLegacyRejectsCoordinatorEvents(t *testing.T) {
	t.Parallel()
	c, st, _ := openCoord(t)
	raw := reportFixture(t)
	imported, err := coordinator.DefaultImporter{}.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	snap := casestore.SnapshotFromImporterResult(imported)
	snap.CoordinatorEvents = []domain.CoordinatorEvent{{
		SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
		EventID: "cevt-111111111111111111111111", CaseID: snap.Case.CaseID,
		EventType: domain.EventCaseLoaded, ActorType: domain.ActorSystem,
		OccurredAt:            snap.Case.UpdatedAt,
		ReferencedDocumentIDs: []string{snap.Case.CaseID},
		ReasonCode:            "case_loaded",
	}}
	info, err := st.Commit(context.Background(), casestore.CommitRequest{
		Snapshot: snap,
		Reason:   casestore.CommitReasonLegacyImport,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AdoptLegacyCase(context.Background(), coordinator.AdoptLegacyCaseRequest{
		CaseID: snap.Case.CaseID, ExpectedCommitID: info.CommitID, Actor: domain.ActorSystem,
	})
	if !errors.Is(err, coordinator.ErrLegacyAdoptionRejected) {
		t.Fatalf("want ErrLegacyAdoptionRejected, got %v", err)
	}
}
