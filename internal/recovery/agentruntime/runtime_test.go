package agentruntime_test

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/agentruntime"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	readops "github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/read"
)

type scriptedProvider struct {
	rounds []agentruntime.ProviderProposal
	i      int
}

func (p *scriptedProvider) Propose(ctx context.Context, input agentruntime.RoundInput) (agentruntime.ProviderProposal, error) {
	if err := ctx.Err(); err != nil {
		return agentruntime.ProviderProposal{}, err
	}
	if p.i >= len(p.rounds) {
		return agentruntime.ProviderProposal{}, context.Canceled
	}
	out := p.rounds[p.i]
	out.CaseID = input.Context.CaseID
	out.Round = input.Round
	out.SchemaVersion = agentruntime.SchemaVersion
	p.i++
	return out, nil
}

type coordinatorPort struct {
	c *coordinator.Coordinator
}

func (p coordinatorPort) LoadCase(ctx context.Context, caseID string) (coordinator.CaseView, error) {
	return p.c.LoadCase(ctx, caseID)
}

func (p coordinatorPort) ExecuteReadOperation(ctx context.Context, req coordinator.ExecuteReadOperationRequest) (coordinator.ExecuteReadOperationResult, error) {
	return p.c.ExecuteReadOperation(ctx, req)
}

func (p coordinatorPort) CommitAgentConsultation(ctx context.Context, req coordinator.CommitAgentConsultationRequest) (coordinator.CommitAgentConsultationResult, error) {
	return p.c.CommitAgentConsultation(ctx, req)
}

func analyzedReady(t *testing.T) (*coordinator.Coordinator, coordinator.CaseView) {
	t.Helper()
	c := openRuntimeCoord(t)
	return c, mustAnalyzedCase(t, c)
}

func TestContextStripsSecrets(t *testing.T) {
	t.Parallel()
	snap := casestore.Snapshot{
		Case: domain.CaseManifest{CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa"},
		EvidenceBundles: []domain.EvidenceBundle{{
			EvidenceID:  "evidence-aaaaaaaaaaaaaaaaaaaaaaaa",
			TargetID:    "target-disk-01",
			FactsSchema: "bitlocker_inventory",
			Facts:       json.RawMessage(`{"status":"locked","recovery_key":"123456-789012-345678-901234-567890-123456-789012-345678","hostname":"SECRET-HOST"}`),
		}},
	}
	ctx := agentruntime.BuildSanitizedContext(snap, "commit-aaaaaaaaaaaaaaaaaaaaaaaa")
	raw, _ := json.Marshal(ctx)
	s := string(raw)
	for _, banned := range []string{"SECRET-HOST", "123456-789012", "recovery_key"} {
		if strings.Contains(s, banned) {
			t.Fatalf("sanitized context leaked %q", banned)
		}
	}
}

func TestAuthorizeRejectsUnknownOperation(t *testing.T) {
	t.Parallel()
	reg, err := readops.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	snap := casestore.Snapshot{
		Case:    domain.CaseManifest{CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa"},
		Targets: []domain.Target{{TargetID: "target-fw-01"}},
	}
	_, err = agentruntime.AuthorizeReadRequests(snap, reg, []agentruntime.ReadRequestDraft{{
		RequestKey: "k1", OperationID: "repair.destroy_disk", OperationVersion: "1.0.0", TargetID: "target-fw-01",
		Parameters: json.RawMessage(`{}`),
	}}, map[string]struct{}{}, 8)
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func TestAuthorizeRejectsCommandParameters(t *testing.T) {
	t.Parallel()
	reg, err := readops.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	snap := casestore.Snapshot{
		Case:    domain.CaseManifest{CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa"},
		Targets: []domain.Target{{TargetID: "target-fw-01"}},
	}
	_, err = agentruntime.AuthorizeReadRequests(snap, reg, []agentruntime.ReadRequestDraft{{
		RequestKey: "k1", OperationID: "boot.inspect_firmware_mode", OperationVersion: "1.0.0", TargetID: "target-fw-01",
		Parameters: json.RawMessage(`{"command":"bcdboot C:\\Windows"}`),
	}}, map[string]struct{}{}, 8)
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func TestInputDigestStable(t *testing.T) {
	t.Parallel()
	a := agentruntime.InputDigest("case-aaaaaaaaaaaaaaaaaaaaaaaa", "creq-aaaaaaaaaaaaaaaaaaaaaaaa", "commit-aaaaaaaaaaaaaaaaaaaaaaaa", "topology-aaaaaaaaaaaaaaaaaaaaaaaa", []string{"finding-bbbbbbbbbbbbbbbbbbbbbbbb", "finding-aaaaaaaaaaaaaaaaaaaaaaaa"})
	b := agentruntime.InputDigest("case-aaaaaaaaaaaaaaaaaaaaaaaa", "creq-aaaaaaaaaaaaaaaaaaaaaaaa", "commit-aaaaaaaaaaaaaaaaaaaaaaaa", "topology-aaaaaaaaaaaaaaaaaaaaaaaa", []string{"finding-aaaaaaaaaaaaaaaaaaaaaaaa", "finding-bbbbbbbbbbbbbbbbbbbbbbbb"})
	if a != b {
		t.Fatal("digest must ignore finding order")
	}
	if len(a) != 64 {
		t.Fatalf("digest len=%d", len(a))
	}
}

func TestNoOSExecInPackage(t *testing.T) {
	t.Parallel()
	dir := "."
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
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), `"os/exec"`) {
			t.Fatalf("%s imports os/exec", path)
		}
		if _, err := parser.ParseFile(fset, path, src, 0); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuntimeCompletedConsultation(t *testing.T) {
	t.Parallel()
	c, view := analyzedReady(t)
	findingID := view.Snapshot.Findings[0].FindingID
	evidenceID := view.Snapshot.EvidenceBundles[0].EvidenceID
	provider := &scriptedProvider{rounds: []agentruntime.ProviderProposal{{
		Status: agentruntime.StatusCompleted,
		Hypotheses: []agentruntime.HypothesisDraft{{
			Code: "bcd_path_mismatch_advisory", Title: "BCD path may be wrong",
			Rationale:                 "Deterministic findings suggest BCD path mismatch; historical bcdboot repair is out of scope.",
			Confidence:                "medium",
			SupportingFindingRefs:     []string{findingID},
			SupportingEvidenceRefs:    []string{evidenceID},
			ContradictingEvidenceRefs: []string{},
			Limitations:               []string{"advisory only"},
		}},
		ReadRequests:        []agentruntime.ReadRequestDraft{},
		NextDiagnosticSteps: []string{"boot.inspect_bcd_store"},
		RetrievedSources:    []agentruntime.SourceDraft{},
		Limitations:         []string{"no live reinspection"},
		ProviderName:        "mock",
	}}}
	rt := agentruntime.Runtime{
		Port:     coordinatorPort{c: c},
		Provider: provider,
		Options:  agentruntime.Options{Now: func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }},
	}
	res, err := rt.Run(context.Background(), agentruntime.Request{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "creq-aaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != agentruntime.StatusCompleted {
		t.Fatalf("status=%s detail=%s", res.Status, res.Detail)
	}
	if res.Consultation == nil {
		t.Fatal("missing consultation")
	}
	if res.CaseView.State != domain.WorkflowAnalyzed {
		t.Fatalf("workflow=%s", res.CaseView.State)
	}
	if len(res.CaseView.Snapshot.RepairPlans) != 0 {
		t.Fatal("repair plans must not be created")
	}
	if res.CaseView.Snapshot.WorkflowState.Revision != view.Snapshot.WorkflowState.Revision {
		t.Fatal("workflow revision changed")
	}

	// Idempotent retry
	again, err := rt.Run(context.Background(), agentruntime.Request{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID, // stale
		RequestID:        "creq-aaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !again.Idempotent {
		t.Fatal("expected idempotent retry")
	}
}

func TestRuntimeRejectsInvalidProposal(t *testing.T) {
	t.Parallel()
	c, view := analyzedReady(t)
	provider := &scriptedProvider{rounds: []agentruntime.ProviderProposal{{
		Status:              "not-a-status",
		Hypotheses:          []agentruntime.HypothesisDraft{},
		ReadRequests:        []agentruntime.ReadRequestDraft{},
		NextDiagnosticSteps: []string{},
		RetrievedSources:    []agentruntime.SourceDraft{},
		Limitations:         []string{"x"},
		ProviderName:        "mock",
	}}}
	rt := agentruntime.Runtime{Port: coordinatorPort{c: c}, Provider: provider}
	res, err := rt.Run(context.Background(), agentruntime.Request{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "creq-bbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if res.Status != agentruntime.StatusFailed && err == nil {
		t.Fatalf("expected failed, got %+v err=%v", res, err)
	}
}
