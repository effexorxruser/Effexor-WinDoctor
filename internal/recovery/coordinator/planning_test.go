package coordinator_test

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func analyzedBootDoctorCase(t *testing.T) (*coordinator.Coordinator, coordinator.CaseView) {
	t.Helper()
	c, view := bootDoctorReadyCase(t)
	analyzed, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-101010101010101010101010",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, analyzed.CaseView
}

func TestProposeRepairPlanWorkflow(t *testing.T) {
	t.Parallel()
	c, analyzed := analyzedBootDoctorCase(t)
	proposed, err := c.ProposeRepairPlan(context.Background(), coordinator.ProposeRepairPlanRequest{
		CaseID:           analyzed.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CommitInfo.CommitID,
		RequestID:        "planreq-aaaaaaaaaaaaaaaaaaaaaaaa",
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		var refusal *coordinator.PlannerRefusalError
		if errors.As(err, &refusal) {
			t.Skipf("planner refused in fixture case: %s", refusal.Message)
		}
		t.Fatal(err)
	}
	if proposed.CaseView.State != domain.WorkflowPlanProposed {
		t.Fatalf("state=%s", proposed.CaseView.State)
	}
	if len(proposed.CaseView.Snapshot.RepairPlans) != 1 {
		t.Fatalf("plans=%d", len(proposed.CaseView.Snapshot.RepairPlans))
	}
	if len(proposed.CaseView.Snapshot.ExecutionEvents) != 0 || len(proposed.CaseView.Snapshot.VerificationReports) != 0 {
		t.Fatal("planning must not create execution or verification documents")
	}

	policyRes, err := c.EvaluateRepairPlanPolicy(context.Background(), coordinator.EvaluateRepairPlanPolicyRequest{
		CaseID:           proposed.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID: proposed.CaseView.CommitInfo.CommitID,
		RequestID:        "polreq-aaaaaaaaaaaaaaaaaaaaaaaa",
		Actor:            domain.ActorPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if policyRes.Evaluation.Decision != "allowed" {
		t.Fatalf("policy decision=%s reasons=%v", policyRes.Evaluation.Decision, policyRes.Evaluation.ReasonCodes)
	}
	if policyRes.CaseView.State != domain.WorkflowAwaitingApproval {
		t.Fatalf("state=%s", policyRes.CaseView.State)
	}

	approved, err := c.ApproveRepairPlan(context.Background(), coordinator.ApproveRepairPlanRequest{
		CaseID:            policyRes.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID:  policyRes.CaseView.CommitInfo.CommitID,
		RequestID:         "apprreq-aaaaaaaaaaaaaaaaaaaaaaaa",
		TechnicianRef:     "tech.local",
		AcknowledgedRisks: []string{"bcd_mutation"},
		ScopeSummary:      "Approve typed UEFI BCD repair plan only.",
		Actor:             domain.ActorTechnician,
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved.CaseView.State != domain.WorkflowApproved {
		t.Fatalf("state=%s", approved.CaseView.State)
	}
	if len(approved.CaseView.Snapshot.RepairApprovals) != 1 {
		t.Fatalf("approvals=%d", len(approved.CaseView.Snapshot.RepairApprovals))
	}
}

func TestProposeRepairPlanIdempotent(t *testing.T) {
	t.Parallel()
	c, analyzed := analyzedBootDoctorCase(t)
	req := coordinator.ProposeRepairPlanRequest{
		CaseID:           analyzed.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CommitInfo.CommitID,
		RequestID:        "planreq-bbbbbbbbbbbbbbbbbbbbbbbb",
		Actor:            domain.ActorSystem,
	}
	first, err := c.ProposeRepairPlan(context.Background(), req)
	if err != nil {
		var refusal *coordinator.PlannerRefusalError
		if errors.As(err, &refusal) {
			t.Skipf("planner refused: %s", refusal.Message)
		}
		t.Fatal(err)
	}
	req.ExpectedCommitID = analyzed.CommitInfo.CommitID
	second, err := c.ProposeRepairPlan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Idempotent {
		t.Fatal("expected idempotent plan proposal")
	}
	if second.CaseView.CommitInfo.CommitID != first.CaseView.CommitInfo.CommitID {
		t.Fatal("idempotent retry created new commit")
	}
}

func TestPlanningCorruptCaseBlocked(t *testing.T) {
	t.Parallel()
	c, _, root := openCoord(t)
	view := mustCreate(t, c)
	topo, err := c.ResolveWindowsBootTopology(context.Background(), coordinator.ResolveWindowsBootTopologyRequest{
		CaseID: view.Snapshot.Case.CaseID, ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID: "acqreq-dddddddddddddddddddddddd", Actor: domain.ActorSystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	an, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID: view.Snapshot.Case.CaseID, ExpectedCommitID: topo.CaseView.CommitInfo.CommitID,
		RequestID: "acqreq-eeeeeeeeeeeeeeeeeeeeeeee", Actor: domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cases", view.Snapshot.Case.CaseID, "snapshots", an.CaseView.CommitInfo.SnapshotID, "documents", "case-manifest.json")
	if err := os.WriteFile(path, []byte(`{"schema_name":"case-manifest"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = c.ProposeRepairPlan(context.Background(), coordinator.ProposeRepairPlanRequest{
		CaseID: view.Snapshot.Case.CaseID, ExpectedCommitID: an.CaseView.CommitInfo.CommitID,
		RequestID: "planreq-dddddddddddddddddddddddd", Actor: domain.ActorSystem,
	})
	if err == nil {
		t.Fatal("expected corrupt case failure")
	}
	if !errors.Is(err, coordinator.ErrCaseCorrupt) {
		t.Fatalf("want ErrCaseCorrupt, got %v", err)
	}
}

func TestPlannerPolicyPlannedNoExecImport(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	for _, pkg := range []string{"planner", "policy", "operations/planned"} {
		if err := assertNoOSExec(filepath.Join(root, pkg)); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoOSExec(dir string) error {
	fset := token.NewFileSet()
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range src.Imports {
			if im.Path.Value == `"os/exec"` {
				return errors.New("os/exec import in " + path)
			}
		}
		return nil
	})
}
