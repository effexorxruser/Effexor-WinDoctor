package coordinator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func TestExecuteReadOperationFromEvidenceCollected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	fw := firmwareTarget(t, view)
	res, err := c.ExecuteReadOperation(context.Background(), coordinator.ExecuteReadOperationRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-aaaaaaaaaaaaaaaaaaaaaaaa",
		OperationID:      "boot.inspect_firmware_mode",
		OperationVersion: "1.0.0",
		TargetID:         fw,
		Parameters:       json.RawMessage(`{}`),
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Idempotent {
		t.Fatal("first call should commit")
	}
	if res.CaseView.CommitInfo.Sequence <= view.CommitInfo.Sequence {
		t.Fatalf("sequence did not advance: %d -> %d", view.CommitInfo.Sequence, res.CaseView.CommitInfo.Sequence)
	}
	if res.CaseView.Snapshot.WorkflowState.Revision != view.Snapshot.WorkflowState.Revision {
		t.Fatalf("workflow revision changed")
	}
	if res.CaseView.State != domain.WorkflowEvidenceCollected {
		t.Fatalf("state %s", res.CaseView.State)
	}
	if len(res.CaseView.Snapshot.CoordinatorEvents) != len(view.Snapshot.CoordinatorEvents) {
		t.Fatal("coordinator events must not change")
	}
	if res.CaseView.Snapshot.Case.CurrentState != view.Snapshot.Case.CurrentState {
		t.Fatal("case current state changed")
	}
	if len(res.CaseView.Snapshot.EvidenceAcquisitions) != 1 {
		t.Fatalf("acquisitions: %d", len(res.CaseView.Snapshot.EvidenceAcquisitions))
	}
	if len(res.CaseView.Snapshot.Findings) != 0 {
		t.Fatal("findings must not be created")
	}
	if len(res.CaseView.Snapshot.RepairPlans) != 0 {
		t.Fatal("plans must not be created")
	}
}

func TestResolveWindowsBootTopologyFromEvidenceCollected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	res, err := c.ResolveWindowsBootTopology(context.Background(), coordinator.ResolveWindowsBootTopologyRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-bbbbbbbbbbbbbbbbbbbbbbbb",
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Topology.TopologyID == "" {
		t.Fatal("missing topology id")
	}
	if res.CaseView.Snapshot.WorkflowState.Revision != view.Snapshot.WorkflowState.Revision {
		t.Fatal("workflow revision changed")
	}
	if len(res.CaseView.Snapshot.Findings) != 0 {
		t.Fatal("resolver must not create findings")
	}
}

func TestAcquisitionStaleCommitRejected(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	fw := firmwareTarget(t, view)
	_, err := c.ExecuteReadOperation(context.Background(), coordinator.ExecuteReadOperationRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: "commit-ffffffffffffffffffffffff",
		RequestID:        "acqreq-cccccccccccccccccccccccc",
		OperationID:      "boot.inspect_firmware_mode",
		OperationVersion: "1.0.0",
		TargetID:         fw,
		Parameters:       json.RawMessage(`{}`),
	})
	if !errors.Is(err, coordinator.ErrCaseRevisionConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestAcquisitionAllowedAfterAnalyzed(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	analyzed, err := c.CommitAnalysis(context.Background(), coordinator.CommitAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		Findings: []domain.Finding{
			sampleFinding(view.Snapshot.Case.CaseID, view.Snapshot.EvidenceBundles[0].EvidenceID, view.Snapshot.Targets[0].TargetID),
		},
		Actor: domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	fw := firmwareTarget(t, analyzed)
	res, err := c.ExecuteReadOperation(context.Background(), coordinator.ExecuteReadOperationRequest{
		CaseID:           analyzed.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CommitInfo.CommitID,
		RequestID:        "acqreq-dddddddddddddddddddddddd",
		OperationID:      "boot.inspect_firmware_mode",
		OperationVersion: "1.0.0",
		TargetID:         fw,
		Parameters:       json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CaseView.State != domain.WorkflowAnalyzed {
		t.Fatalf("state=%s", res.CaseView.State)
	}
	if res.CaseView.Snapshot.WorkflowState.Revision != analyzed.Snapshot.WorkflowState.Revision {
		t.Fatal("workflow revision must not change")
	}
}

func TestAcquisitionIdempotentAndConflict(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	fw := firmwareTarget(t, view)
	req := coordinator.ExecuteReadOperationRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-eeeeeeeeeeeeeeeeeeeeeeee",
		OperationID:      "boot.inspect_firmware_mode",
		OperationVersion: "1.0.0",
		TargetID:         fw,
		Parameters:       json.RawMessage(`{}`),
	}
	first, err := c.ExecuteReadOperation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.ExpectedCommitID = first.CaseView.CommitInfo.CommitID
	second, err := c.ExecuteReadOperation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Idempotent {
		t.Fatal("expected idempotent")
	}
	if second.CaseView.CommitInfo.CommitID != first.CaseView.CommitInfo.CommitID {
		t.Fatal("idempotent must not create new commit")
	}
	req.OperationID = "bitlocker.inspect_inventory"
	_, err = c.ExecuteReadOperation(context.Background(), req)
	if !errors.Is(err, coordinator.ErrAcquisitionConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestAcquisitionStaleCommitIdempotent(t *testing.T) {
	t.Parallel()
	c, _, _ := openCoord(t)
	view := mustCreate(t, c)
	fw := firmwareTarget(t, view)
	staleCommit := view.CommitInfo.CommitID
	req := coordinator.ExecuteReadOperationRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: staleCommit,
		RequestID:        "acqreq-ffffffffffffffffffffffff",
		OperationID:      "boot.inspect_firmware_mode",
		OperationVersion: "1.0.0",
		TargetID:         fw,
		Parameters:       json.RawMessage(`{}`),
		Actor:            domain.ActorSystem,
	}
	first, err := c.ExecuteReadOperation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Idempotent {
		t.Fatal("first call should commit")
	}
	if first.CaseView.CommitInfo.CommitID == staleCommit {
		t.Fatal("commit should advance after first acquisition")
	}
	acqCount := len(first.CaseView.Snapshot.EvidenceAcquisitions)

	req.ExpectedCommitID = staleCommit
	second, err := c.ExecuteReadOperation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Idempotent {
		t.Fatal("stale commit retry with same request_id must be idempotent")
	}
	if second.Evidence.EvidenceID != first.Evidence.EvidenceID {
		t.Fatal("idempotent retry must return same evidence")
	}
	if len(second.CaseView.Snapshot.EvidenceAcquisitions) != acqCount {
		t.Fatalf("acquisition count changed: %d -> %d", acqCount, len(second.CaseView.Snapshot.EvidenceAcquisitions))
	}

	req.OperationID = "bitlocker.inspect_inventory"
	_, err = c.ExecuteReadOperation(context.Background(), req)
	if !errors.Is(err, coordinator.ErrAcquisitionConflict) {
		t.Fatalf("same request_id different operation: got %v", err)
	}

	req.OperationID = "boot.inspect_firmware_mode"
	req.RequestID = "acqreq-111111111111111111111112"
	_, err = c.ExecuteReadOperation(context.Background(), req)
	if !errors.Is(err, coordinator.ErrCaseRevisionConflict) {
		t.Fatalf("new request_id with stale commit: got %v", err)
	}
}

func firmwareTarget(t *testing.T, view coordinator.CaseView) string {
	t.Helper()
	for _, tgt := range view.Snapshot.Targets {
		if tgt.TargetType == "firmware" {
			return tgt.TargetID
		}
	}
	t.Fatal("firmware target missing")
	return ""
}
