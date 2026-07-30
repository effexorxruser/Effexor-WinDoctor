package coordinator_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestCreateCaseAlreadyExists(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	raw := reportFixture(t)
	first, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
	if !errors.Is(err, coordinator.ErrCaseAlreadyExists) {
		t.Fatalf("want ErrCaseAlreadyExists, got %v", err)
	}
	loaded, err := c.LoadCase(context.Background(), first.Snapshot.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommitInfo.CommitID != first.CommitInfo.CommitID {
		t.Fatal("duplicate CreateCase mutated case")
	}
	if loaded.State != domain.WorkflowEvidenceCollected {
		t.Fatalf("workflow reset: %s", loaded.State)
	}
}

func TestCreateCaseRejectedAfterAnalyzed(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	raw := reportFixture(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(caseID,
			view.Snapshot.EvidenceBundles[0].EvidenceID,
			view.Snapshot.Targets[0].TargetID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
	if !errors.Is(err, coordinator.ErrCaseAlreadyExists) {
		t.Fatalf("want ErrCaseAlreadyExists, got %v", err)
	}
	loaded, err := c.LoadCase(context.Background(), caseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommitInfo.CommitID != analyzed.CommitInfo.CommitID || loaded.State != domain.WorkflowAnalyzed {
		t.Fatal("CreateCase after analyzed mutated case")
	}
}

func TestConcurrentCreateCase(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	raw := reportFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var success, exists, busy, other int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, coordinator.ErrCaseAlreadyExists):
			exists++
		case errors.Is(err, coordinator.ErrCaseBusy):
			busy++
		default:
			other++
			t.Logf("other: %v", err)
		}
	}
	if success != 1 || (exists+busy) != 1 || other != 0 {
		t.Fatalf("success=%d exists=%d busy=%d other=%d", success, exists, busy, other)
	}
}

func TestCreateCaseCorruptExisting(t *testing.T) {
	t.Parallel()
	c, _, root := openCoord(t)
	raw := reportFixture(t)
	view, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cases", view.Snapshot.Case.CaseID, "snapshots", view.CommitInfo.SnapshotID, "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
	if err == nil {
		t.Fatal("expected failure against corrupt existing case")
	}
	// Create-only must not publish a new snapshot; presence of a head (even corrupt)
	// surfaces as already-exists or integrity/corrupt depending on chain verification.
	if !errors.Is(err, coordinator.ErrCaseAlreadyExists) &&
		!errors.Is(err, coordinator.ErrCaseCorrupt) &&
		!errors.Is(err, casestore.ErrCaseExists) &&
		!errors.Is(err, casestore.ErrIntegrity) {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestCreateCaseExistingLegacy(t *testing.T) {
	t.Parallel()
	c, st, _ := openCoord(t)
	raw := reportFixture(t)
	imported, err := coordinator.DefaultImporter{}.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	snap := casestore.SnapshotFromImporterResult(imported)
	info, err := st.Commit(context.Background(), casestore.CommitRequest{
		Snapshot: snap,
		Reason:   casestore.CommitReasonLegacyImport,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: raw})
	if !errors.Is(err, coordinator.ErrCaseAlreadyExists) {
		t.Fatalf("want ErrCaseAlreadyExists against legacy head, got %v", err)
	}
	loaded, err := c.LoadCase(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommitInfo.CommitID != info.CommitID {
		t.Fatal("CreateCase mutated existing legacy case")
	}
	if loaded.Snapshot.WorkflowState != nil {
		t.Fatal("CreateCase must not adopt legacy workflow")
	}
}

func TestAdoptLegacyCaseThenAnalyze(t *testing.T) {
	t.Parallel()
	c, st, _ := openCoord(t)
	raw := reportFixture(t)
	imported, err := coordinator.DefaultImporter{}.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	snap := casestore.SnapshotFromImporterResult(imported)
	info, err := st.Commit(context.Background(), casestore.CommitRequest{
		Snapshot: snap,
		Reason:   casestore.CommitReasonLegacyImport,
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := c.LoadCase(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Snapshot.WorkflowState != nil {
		t.Fatal("legacy load should have nil workflow")
	}
	adopted, err := c.AdoptLegacyCase(context.Background(), coordinator.AdoptLegacyCaseRequest{
		CaseID:           snap.Case.CaseID,
		ExpectedCommitID: info.CommitID,
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	if adopted.State != domain.WorkflowEvidenceCollected {
		t.Fatalf("state=%s", adopted.State)
	}
	if adopted.Snapshot.Case.CurrentState != domain.CaseStateSnapshotted {
		t.Fatalf("manifest state=%s", adopted.Snapshot.Case.CurrentState)
	}
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           snap.Case.CaseID,
		ExpectedCommitID: adopted.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(snap.Case.CaseID,
			adopted.Snapshot.EvidenceBundles[0].EvidenceID,
			adopted.Snapshot.Targets[0].TargetID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if analyzed.State != domain.WorkflowAnalyzed || analyzed.Snapshot.Case.CurrentState != domain.CaseStateDiagnosed {
		t.Fatalf("analyzed state workflow=%s manifest=%s", analyzed.State, analyzed.Snapshot.Case.CurrentState)
	}
}

func TestCommitPlanDraftOnly(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	tg := view.Snapshot.Targets[0].TargetID
	ev := view.Snapshot.EvidenceBundles[0].EvidenceID
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: caseID, ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(caseID, ev, tg)},
	})
	if err != nil {
		t.Fatal(err)
	}

	reject := func(name string, mutate func(*domain.RepairPlan)) {
		t.Helper()
		plan := samplePlan(caseID, "finding-cccccccccccccccccccccccc", tg)
		mutate(&plan)
		_, err := c.CommitPlan(context.Background(), coordinator.CommitPlanRequest{
			CaseID: caseID, ExpectedCommitID: analyzed.CommitInfo.CommitID, Plan: plan,
		})
		if err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
	reject("approved", func(p *domain.RepairPlan) { p.Status = "approved" })
	reject("awaiting_approval", func(p *domain.RepairPlan) { p.Status = "awaiting_approval" })
	reject("empty findings", func(p *domain.RepairPlan) { p.FindingRefs = []string{} })
	reject("empty steps", func(p *domain.RepairPlan) { p.Steps = []domain.PlanStep{} })

	okPlan := samplePlan(caseID, "finding-cccccccccccccccccccccccc", tg)
	planned, err := c.CommitPlan(context.Background(), coordinator.CommitPlanRequest{
		CaseID: caseID, ExpectedCommitID: analyzed.CommitInfo.CommitID, Plan: okPlan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if planned.State != domain.WorkflowPlanProposed {
		t.Fatalf("state=%s", planned.State)
	}
}

func TestMonotonicTimestamps(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, clockAt time.Time) {
		t.Helper()
		root := t.TempDir()
		st, err := casestore.Open(root, casestore.Options{
			Clock:   fixedClock{t: clockAt},
			Entropy: &cyclicEntropy{pattern: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
			Clock: fixedClock{t: clockAt},
			IDs:   &seqIDs{},
		})
		if err != nil {
			t.Fatal(err)
		}
		view, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: reportFixture(t)})
		if err != nil {
			t.Fatal(err)
		}
		createdAt, err := time.Parse(time.RFC3339, view.Snapshot.Case.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		updatedAt, err := time.Parse(time.RFC3339, view.Snapshot.Case.UpdatedAt)
		if err != nil {
			t.Fatal(err)
		}
		if updatedAt.Before(createdAt) {
			t.Fatalf("updated_at %s before created_at %s", updatedAt, createdAt)
		}
		analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
			CaseID:           view.Snapshot.Case.CaseID,
			ExpectedCommitID: view.CommitInfo.CommitID,
			Findings: []domain.Finding{sampleFinding(view.Snapshot.Case.CaseID,
				view.Snapshot.EvidenceBundles[0].EvidenceID,
				view.Snapshot.Targets[0].TargetID)},
		})
		if err != nil {
			t.Fatal(err)
		}
		nextUpdated, err := time.Parse(time.RFC3339, analyzed.Snapshot.Case.UpdatedAt)
		if err != nil {
			t.Fatal(err)
		}
		if nextUpdated.Before(updatedAt) {
			t.Fatalf("analysis updated_at went backwards: %s < %s", nextUpdated, updatedAt)
		}
	}

	t.Run("clock_before_report", func(t *testing.T) {
		t.Parallel()
		run(t, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	})
	t.Run("same_clock", func(t *testing.T) {
		t.Parallel()
		run(t, time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC))
	})
	t.Run("forward_clock", func(t *testing.T) {
		t.Parallel()
		run(t, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	})
	t.Run("clock_before_previous_transition", func(t *testing.T) {
		t.Parallel()
		clock := &mutableClock{t: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)}
		root := t.TempDir()
		st, err := casestore.Open(root, casestore.Options{
			Clock:   clock,
			Entropy: &cyclicEntropy{pattern: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		})
		if err != nil {
			t.Fatal(err)
		}
		c, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
			Clock: clock,
			IDs:   &seqIDs{},
		})
		if err != nil {
			t.Fatal(err)
		}
		view, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{DiagnosticReport: reportFixture(t)})
		if err != nil {
			t.Fatal(err)
		}
		prev := view.Snapshot.Case.UpdatedAt
		clock.set(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
		analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
			CaseID:           view.Snapshot.Case.CaseID,
			ExpectedCommitID: view.CommitInfo.CommitID,
			Findings: []domain.Finding{sampleFinding(view.Snapshot.Case.CaseID,
				view.Snapshot.EvidenceBundles[0].EvidenceID,
				view.Snapshot.Targets[0].TargetID)},
		})
		if err != nil {
			t.Fatal(err)
		}
		nextUpdated, err := time.Parse(time.RFC3339, analyzed.Snapshot.Case.UpdatedAt)
		if err != nil {
			t.Fatal(err)
		}
		prevUpdated, err := time.Parse(time.RFC3339, prev)
		if err != nil {
			t.Fatal(err)
		}
		if nextUpdated.Before(prevUpdated) {
			t.Fatalf("updated_at went backwards despite earlier clock: %s < %s", nextUpdated, prevUpdated)
		}
	})
}

type mutableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mutableClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func TestManifestWorkflowSync(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	if view.Snapshot.Case.CurrentState != domain.CaseStateSnapshotted {
		t.Fatalf("create manifest=%s", view.Snapshot.Case.CurrentState)
	}
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID: view.Snapshot.Case.CaseID, ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(view.Snapshot.Case.CaseID,
			view.Snapshot.EvidenceBundles[0].EvidenceID,
			view.Snapshot.Targets[0].TargetID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if analyzed.Snapshot.Case.CurrentState != domain.CaseStateDiagnosed {
		t.Fatalf("analyzed manifest=%s", analyzed.Snapshot.Case.CurrentState)
	}
}
