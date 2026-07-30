package coordinator_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func containsRef(refs []string, id string) bool {
	for _, r := range refs {
		if r == id {
			return true
		}
	}
	return false
}

func TestAppendOnlyFindingsAcrossAnalyses(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	ev := view.Snapshot.EvidenceBundles[0].EvidenceID
	tg := view.Snapshot.Targets[0].TargetID

	findingA := sampleFinding(caseID, ev, tg)
	a, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: view.CommitInfo.CommitID, Findings: []domain.Finding{findingA},
	})
	if err != nil {
		t.Fatal(err)
	}
	findingB := sampleFinding(caseID, ev, tg)
	findingB.FindingID = "finding-bbbbbbbbbbbbbbbbbbbbbbbb"
	findingB.Title = "Second analysis finding"
	b, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: a.CommitInfo.CommitID, Findings: []domain.Finding{findingB},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Snapshot.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(b.Snapshot.Findings))
	}
	ids := map[string]struct{}{}
	for _, f := range b.Snapshot.Findings {
		ids[f.FindingID] = struct{}{}
	}
	if _, ok := ids[findingA.FindingID]; !ok {
		t.Fatal("finding A missing from latest snapshot")
	}
	if _, ok := ids[findingB.FindingID]; !ok {
		t.Fatal("finding B missing from latest snapshot")
	}

	var evA, evB *domain.CoordinatorEvent
	for i := range b.Snapshot.CoordinatorEvents {
		ev := &b.Snapshot.CoordinatorEvents[i]
		if ev.EventType == domain.EventAnalysisCommitted && ev.WorkflowRevision == 2 {
			evA = ev
		}
		if ev.EventType == domain.EventAnalysisCommitted && ev.WorkflowRevision == 3 {
			evB = ev
		}
	}
	if evA == nil || evB == nil {
		t.Fatalf("missing analysis events: a=%v b=%v", evA != nil, evB != nil)
	}
	if !containsRef(evA.ReferencedDocumentIDs, findingA.FindingID) {
		t.Fatal("analysis A refs missing finding A")
	}
	if containsRef(evA.ReferencedDocumentIDs, findingB.FindingID) {
		t.Fatal("analysis A refs must not include finding B")
	}
	if !containsRef(evB.ReferencedDocumentIDs, findingB.FindingID) {
		t.Fatal("analysis B refs missing finding B")
	}
	if containsRef(evB.ReferencedDocumentIDs, findingA.FindingID) {
		t.Fatal("analysis B refs must not include finding A")
	}
	if containsRef(evB.ReferencedDocumentIDs, "plan-dddddddddddddddddddddddd") {
		t.Fatal("analysis refs must not include unrelated plan")
	}
}

func TestDivergentFindingIDRejected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	ev := view.Snapshot.EvidenceBundles[0].EvidenceID
	tg := view.Snapshot.Targets[0].TargetID
	first := sampleFinding(caseID, ev, tg)
	a, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: view.CommitInfo.CommitID, Findings: []domain.Finding{first},
	})
	if err != nil {
		t.Fatal(err)
	}
	mutated := first
	mutated.Title = "quietly replaced content"
	_, err = c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: a.CommitInfo.CommitID, Findings: []domain.Finding{mutated},
	})
	if !errors.Is(err, coordinator.ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument, got %v", err)
	}
}

func TestIdenticalFindingIDNoOp(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	ev := view.Snapshot.EvidenceBundles[0].EvidenceID
	tg := view.Snapshot.Targets[0].TargetID
	finding := sampleFinding(caseID, ev, tg)
	a, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: view.CommitInfo.CommitID, Findings: []domain.Finding{finding},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: a.CommitInfo.CommitID, Findings: []domain.Finding{finding},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Snapshot.Findings) != 1 {
		t.Fatalf("want 1 finding after identical refresh, got %d", len(b.Snapshot.Findings))
	}
}

func TestWorkflowRevisionWithSameOccurredAtAndReverseEventIDs(t *testing.T) {
	t.Parallel()
	clockAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	st, err := casestore.Open(root, casestore.Options{
		Clock:   fixedClock{t: clockAt},
		Entropy: &cyclicEntropy{pattern: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := &scriptedIDs{values: []string{
		"cevt-ffffffffffffffffffffffff",
		"cevt-eeeeeeeeeeeeeeeeeeeeeeee",
		"cevt-000000000000000000000001",
	}}
	c, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
		Clock: fixedClock{t: clockAt},
		IDs:   ids,
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
	if b.Snapshot.WorkflowState.Revision != 3 {
		t.Fatalf("revision=%d", b.Snapshot.WorkflowState.Revision)
	}
	if b.Snapshot.WorkflowState.LastTransitionID != "cevt-000000000000000000000001" {
		t.Fatalf("last_transition_id=%s", b.Snapshot.WorkflowState.LastTransitionID)
	}
	times := map[string]string{}
	for _, ev := range b.Snapshot.CoordinatorEvents {
		if domain.IsStateChangingCoordinatorEventType(ev.EventType) {
			times[ev.EventID] = ev.OccurredAt
		}
	}
	if times["cevt-eeeeeeeeeeeeeeeeeeeeeeee"] != times["cevt-000000000000000000000001"] {
		t.Fatalf("expected identical occurred_at; got %#v", times)
	}
}

type scriptedIDs struct {
	mu     sync.Mutex
	i      int
	values []string
}

func (s *scriptedIDs) NewID(prefix string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.i >= len(s.values) {
		return "", fmt.Errorf("scripted IDs exhausted for prefix %s", prefix)
	}
	id := s.values[s.i]
	s.i++
	return id, nil
}

func TestCommitPlanPersistsAuditedPlan(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	ev := view.Snapshot.EvidenceBundles[0].EvidenceID
	tg := view.Snapshot.Targets[0].TargetID
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(caseID, ev, tg)},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := samplePlan(caseID, "finding-cccccccccccccccccccccccc", tg)
	planned, err := c.CommitPlan(context.Background(), coordinator.CommitPlanRequest{
		CaseID: caseID, ExpectedCommitID: analyzed.CommitInfo.CommitID, Plan: plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(planned.Snapshot.RepairPlans) != 1 {
		t.Fatalf("want 1 plan, got %d", len(planned.Snapshot.RepairPlans))
	}
	if planned.Snapshot.WorkflowState.ActivePlanID != plan.PlanID {
		t.Fatalf("active plan mismatch")
	}
}
