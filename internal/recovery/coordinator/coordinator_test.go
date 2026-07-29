package coordinator_test

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (s *seqIDs) NewID(prefix string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return fmt.Sprintf("%s-%024x", prefix, s.n), nil
}

type cyclicEntropy struct {
	pattern []byte
	off     int
}

func (c *cyclicEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.pattern[c.off%len(c.pattern)]
		c.off++
	}
	return len(p), nil
}

func openCoord(t *testing.T) (*coordinator.Coordinator, *casestore.Store, string) {
	t.Helper()
	root := t.TempDir()
	st, err := casestore.Open(root, casestore.Options{
		Clock:   fixedClock{t: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)},
		Entropy: &cyclicEntropy{pattern: []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0xaa, 0xbb}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
		Clock: fixedClock{t: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)},
		IDs:   &seqIDs{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, st, root
}

func reportFixture(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "importer", "legacyreport", "testdata", "report-uefi-bitlocker-unavailable.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustCreate(t *testing.T, c *coordinator.Coordinator) coordinator.CaseView {
	t.Helper()
	view, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{
		DiagnosticReport: reportFixture(t),
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	return view
}

func sampleFinding(caseID, evidenceID, targetID string) domain.Finding {
	return domain.Finding{
		SchemaName:           domain.SchemaFinding,
		SchemaVersion:        domain.SchemaVersion,
		FindingID:            "finding-cccccccccccccccccccccccc",
		CaseID:               caseID,
		Severity:             "medium",
		Confidence:           "medium",
		Title:                "Boot topology unresolved",
		Rationale:            "Deterministic analyzer placeholder finding for coordinator tests.",
		EvidenceRefs:         []string{evidenceID},
		AffectedTargetIDs:    []string{targetID},
		RecommendedWorkflows: []string{},
		Limitations:          []string{"test fixture"},
	}
}

func samplePlan(caseID, findingID, targetID string) domain.RepairPlan {
	return domain.RepairPlan{
		SchemaName:    domain.SchemaRepairPlan,
		SchemaVersion: domain.SchemaVersion,
		PlanID:        "plan-dddddddddddddddddddddddd",
		CaseID:        caseID,
		FindingRefs:   []string{findingID},
		Steps: []domain.PlanStep{{
			StepID:           "step-1",
			OperationID:      "boot.inspect_bcd",
			OperationVersion: "1.0.0",
			TargetID:         targetID,
			DependsOn:        []string{},
		}},
		RiskSummary:          "Document-only plan persistence test.",
		BackupRequirements:   []string{},
		ApprovalRequirements: []string{},
		Status:               "draft",
	}
}

func TestCreateCaseEvidenceCollected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	if view.State != domain.WorkflowEvidenceCollected {
		t.Fatalf("state=%s", view.State)
	}
	if view.Snapshot.Case.CaseID == "" || len(view.Snapshot.Targets) == 0 || len(view.Snapshot.EvidenceBundles) == 0 {
		t.Fatalf("imported documents missing")
	}
	if view.Snapshot.WorkflowState == nil {
		t.Fatal("workflow missing")
	}
	if len(view.Snapshot.CoordinatorEvents) == 0 {
		t.Fatal("audit event missing")
	}
	if view.CommitInfo.CommitID == "" {
		t.Fatal("commit missing")
	}
}

func TestLoadCaseRoundTrip(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	created := mustCreate(t, c)
	loaded, err := c.LoadCase(context.Background(), created.Snapshot.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommitInfo.CommitID != created.CommitInfo.CommitID {
		t.Fatalf("commit mismatch")
	}
	if loaded.State != domain.WorkflowEvidenceCollected {
		t.Fatalf("state=%s", loaded.State)
	}
}

func TestCommitAnalysisAndRefresh(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	evID := view.Snapshot.EvidenceBundles[0].EvidenceID
	tgID := view.Snapshot.Targets[0].TargetID

	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings:         []domain.Finding{sampleFinding(caseID, evID, tgID)},
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if analyzed.State != domain.WorkflowAnalyzed {
		t.Fatalf("state=%s", analyzed.State)
	}
	if len(analyzed.Snapshot.Findings) != 1 {
		t.Fatalf("findings=%d", len(analyzed.Snapshot.Findings))
	}

	refreshed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: analyzed.CommitInfo.CommitID,
		Findings:         []domain.Finding{sampleFinding(caseID, evID, tgID)},
		Actor:            domain.ActorDeterministicAnalyzer,
		ReasonCode:       "analysis_refreshed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.State != domain.WorkflowAnalyzed {
		t.Fatalf("refresh state=%s", refreshed.State)
	}
	if refreshed.CommitInfo.CommitID == analyzed.CommitInfo.CommitID {
		t.Fatal("expected new commit on analysis refresh")
	}
}

func TestCommitPlan(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	evID := view.Snapshot.EvidenceBundles[0].EvidenceID
	tgID := view.Snapshot.Targets[0].TargetID
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings:         []domain.Finding{sampleFinding(caseID, evID, tgID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := c.CommitPlan(context.Background(), coordinator.CommitPlanRequest{
		CaseID:           caseID,
		ExpectedCommitID: analyzed.CommitInfo.CommitID,
		Plan:             samplePlan(caseID, "finding-cccccccccccccccccccccccc", tgID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if planned.State != domain.WorkflowPlanProposed {
		t.Fatalf("state=%s", planned.State)
	}
	if planned.Snapshot.WorkflowState.ActivePlanID != "plan-dddddddddddddddddddddddd" {
		t.Fatalf("active plan=%s", planned.Snapshot.WorkflowState.ActivePlanID)
	}
}

func TestIllegalTransitionRejected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	_, err := c.CommitPlan(context.Background(), coordinator.CommitPlanRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Plan:             samplePlan(view.Snapshot.Case.CaseID, "finding-cccccccccccccccccccccccc", view.Snapshot.Targets[0].TargetID),
	})
	if err == nil {
		t.Fatal("expected illegal transition")
	}
	if !errors.Is(err, coordinator.ErrIllegalTransition) {
		t.Fatalf("want ErrIllegalTransition, got %v", err)
	}
}

func TestRevisionConflictRejected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	evID := view.Snapshot.EvidenceBundles[0].EvidenceID
	tgID := view.Snapshot.Targets[0].TargetID
	_, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings:         []domain.Finding{sampleFinding(caseID, evID, tgID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: view.CommitInfo.CommitID, // stale
		Findings:         []domain.Finding{sampleFinding(caseID, evID, tgID)},
	})
	if err == nil {
		t.Fatal("expected conflict")
	}
	if !errors.Is(err, coordinator.ErrCaseRevisionConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	var conflict *coordinator.RevisionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("want RevisionConflictError, got %T", err)
	}
	if conflict.ExpectedCommitID != view.CommitInfo.CommitID {
		t.Fatalf("expected commit field mismatch")
	}
}

func TestCorruptCaseBlocksCoordinator(t *testing.T) {
	t.Parallel()
	c, _, root := openCoord(t)
	view := mustCreate(t, c)
	path := filepath.Join(root, "cases", view.Snapshot.Case.CaseID, "snapshots", view.CommitInfo.SnapshotID, "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := c.LoadCase(context.Background(), view.Snapshot.Case.CaseID)
	if err == nil {
		t.Fatal("expected corrupt load failure")
	}
	if !errors.Is(err, coordinator.ErrCaseCorrupt) {
		t.Fatalf("want ErrCaseCorrupt, got %v", err)
	}
}

func TestFailedTransitionProducesNoCommit(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	before := view.CommitInfo.CommitID
	_, err := c.CommitPlan(context.Background(), coordinator.CommitPlanRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: before,
		Plan:             samplePlan(view.Snapshot.Case.CaseID, "finding-cccccccccccccccccccccccc", view.Snapshot.Targets[0].TargetID),
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	loaded, err := c.LoadCase(context.Background(), view.Snapshot.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CommitInfo.CommitID != before {
		t.Fatalf("commit changed after failed transition")
	}
}

func TestConcurrentUpdatesOnlyOneSucceeds(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	caseID := view.Snapshot.Case.CaseID
	evID := view.Snapshot.EvidenceBundles[0].EvidenceID
	tgID := view.Snapshot.Targets[0].TargetID
	req := coordinator.CommitAnalysisRequest{
		CaseID:           caseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings:         []domain.Finding{sampleFinding(caseID, evID, tgID)},
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.CommitAnalysis(context.Background(), req)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var success, lost, other int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, coordinator.ErrCaseRevisionConflict),
			errors.Is(err, casestore.ErrCaseLocked):
			lost++
		default:
			other++
			t.Logf("other err: %v", err)
		}
	}
	if success != 1 || lost != 1 || other != 0 {
		t.Fatalf("success=%d lost=%d other=%d", success, lost, other)
	}
}

func TestIdempotentIdenticalSnapshotRetry(t *testing.T) {
	t.Parallel()
	c, st, _ := openCoord(t)
	view := mustCreate(t, c)
	// Re-commit identical snapshot via store (coordinator CreateCase already published).
	info, err := st.Commit(context.Background(), casestore.CommitRequest{
		Snapshot: view.Snapshot,
		Reason:   casestore.CommitReasonLegacyImport,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !info.Idempotent {
		t.Fatal("expected idempotent store retry")
	}
	if info.CommitID != view.CommitInfo.CommitID {
		t.Fatal("idempotent retry changed commit")
	}
}

func TestActorRestrictions(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	_, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{sampleFinding(
			view.Snapshot.Case.CaseID,
			view.Snapshot.EvidenceBundles[0].EvidenceID,
			view.Snapshot.Targets[0].TargetID,
		)},
		Actor: domain.ActorLLMAdvisor,
	})
	if err == nil {
		t.Fatal("expected actor rejection")
	}
}

func TestFailAndCancel(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	failed, err := c.FailCase(context.Background(), coordinator.FailCaseRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Actor:            domain.ActorTechnician,
		ReasonCode:       "technician_aborted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != domain.WorkflowFailed {
		t.Fatalf("state=%s", failed.State)
	}

	c2, _, _ := openCoord(t)
	view2 := mustCreate(t, c2)
	cancelled, err := c2.CancelCase(context.Background(), coordinator.CancelCaseRequest{
		CaseID:           view2.Snapshot.Case.CaseID,
		ExpectedCommitID: view2.CommitInfo.CommitID,
		Actor:            domain.ActorTechnician,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != domain.WorkflowCancelled {
		t.Fatalf("state=%s", cancelled.State)
	}
}

func TestNoGatewayOrExecutorImports(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	dir := filepath.Join(filepath.Dir(file))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "/gateway") ||
				strings.Contains(path, "/agentloop") ||
				strings.Contains(path, "/executor") ||
				strings.Contains(path, "openai") {
				t.Fatalf("%s imports forbidden package %s", e.Name(), path)
			}
		}
	}
}

func TestStoreRootContainment(t *testing.T) {
	t.Parallel()
	c, _, root := openCoord(t)
	view := mustCreate(t, c)
	caseDir := filepath.Join(root, "cases", view.Snapshot.Case.CaseID)
	err := filepath.Walk(caseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "..") {
			t.Fatalf("path escaped root: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
