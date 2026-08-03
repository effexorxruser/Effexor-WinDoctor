package coordinator_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func bootDoctorReadyCase(t *testing.T) (*coordinator.Coordinator, coordinator.CaseView) {
	t.Helper()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	topo, err := c.ResolveWindowsBootTopology(context.Background(), coordinator.ResolveWindowsBootTopologyRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-bbbbbbbbbbbbbbbbbbbbbbbb",
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatalf("ResolveWindowsBootTopology: %v", err)
	}
	return c, topo.CaseView
}

func TestCommitBootDoctorAnalysisHappyPath(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	res, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-cccccccccccccccccccccccc",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Idempotent {
		t.Fatal("first commit must not be idempotent")
	}
	if res.CaseView.State != domain.WorkflowAnalyzed {
		t.Fatalf("state=%s", res.CaseView.State)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if len(res.CaseView.Snapshot.Findings) == 0 {
		t.Fatal("case must persist findings")
	}
}

func TestCommitBootDoctorAnalysisStaleCommitIdempotent(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	staleCommit := view.CommitInfo.CommitID
	req := coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: staleCommit,
		RequestID:        "acqreq-dddddddddddddddddddddddd",
		Actor:            domain.ActorDeterministicAnalyzer,
	}
	first, err := c.CommitBootDoctorAnalysis(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Idempotent {
		t.Fatal("first call should commit")
	}
	if first.CaseView.CommitInfo.CommitID == staleCommit {
		t.Fatal("commit should advance")
	}

	req.ExpectedCommitID = staleCommit
	second, err := c.CommitBootDoctorAnalysis(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Idempotent {
		t.Fatal("stale commit retry with same request_id must be idempotent")
	}
	if second.CaseView.CommitInfo.CommitID != first.CaseView.CommitInfo.CommitID {
		t.Fatal("idempotent retry must not create new commit")
	}
	if len(second.Findings) != len(first.Findings) {
		t.Fatalf("findings count changed: %d -> %d", len(first.Findings), len(second.Findings))
	}
}

func TestCommitBootDoctorAnalysisRequestIDConflict(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	requestID := "acqreq-eeeeeeeeeeeeeeeeeeeeeeee"
	_, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{
			sampleFinding(
				view.Snapshot.Case.CaseID,
				view.Snapshot.EvidenceBundles[0].EvidenceID,
				view.Snapshot.Targets[0].TargetID,
			),
		},
		Actor:      domain.ActorDeterministicAnalyzer,
		CommandID:  requestID,
		ReasonCode: "test_placeholder_analysis",
	})
	if err != nil {
		t.Fatal(err)
	}

	analyzed, err := c.LoadCase(context.Background(), view.Snapshot.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           analyzed.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CommitInfo.CommitID,
		RequestID:        requestID,
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if !errors.Is(err, coordinator.ErrAcquisitionConflict) {
		t.Fatalf("expected acquisition conflict, got %v", err)
	}
}

func TestCommitBootDoctorAnalysisCorruptCaseBlocked(t *testing.T) {
	t.Parallel()
	c, _, root := openCoord(t)
	view := mustCreate(t, c)
	topo, err := c.ResolveWindowsBootTopology(context.Background(), coordinator.ResolveWindowsBootTopologyRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-bbbbbbbbbbbbbbbbbbbbbbbb",
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cases", view.Snapshot.Case.CaseID, "snapshots", topo.CaseView.CommitInfo.SnapshotID, "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: topo.CaseView.CommitInfo.CommitID,
		RequestID:        "acqreq-111111111111111111111111",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err == nil {
		t.Fatal("expected corrupt case failure")
	}
	if !errors.Is(err, coordinator.ErrCaseCorrupt) {
		t.Fatalf("want ErrCaseCorrupt, got %v", err)
	}
}

func TestCommitBootDoctorAnalysisStaleCommitNewRequestID(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	staleCommit := view.CommitInfo.CommitID
	first, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: staleCommit,
		RequestID:        "acqreq-222222222222222222222222",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           first.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID: staleCommit,
		RequestID:        "acqreq-333333333333333333333333",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if !errors.Is(err, coordinator.ErrCaseRevisionConflict) {
		t.Fatalf("new request_id with stale commit: got %v", err)
	}
}

func TestCommitBootDoctorAnalysisRejectsLLMActor(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	_, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-444444444444444444444444",
		Actor:            domain.ActorLLMAdvisor,
	})
	if !errors.Is(err, coordinator.ErrActorNotAllowed) {
		t.Fatalf("got %v", err)
	}
}
