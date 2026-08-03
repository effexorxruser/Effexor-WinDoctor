package coordinator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func sampleConsultation(view coordinator.CaseView, requestID string) domain.AgentConsultation {
	findings := make([]string, 0, len(view.Snapshot.Findings))
	for _, f := range view.Snapshot.Findings {
		findings = append(findings, f.FindingID)
	}
	evidence := make([]string, 0, len(view.Snapshot.EvidenceBundles))
	for _, e := range view.Snapshot.EvidenceBundles {
		evidence = append(evidence, e.EvidenceID)
	}
	targets := make([]string, 0, len(view.Snapshot.Targets))
	for _, t := range view.Snapshot.Targets {
		targets = append(targets, t.TargetID)
	}
	return domain.AgentConsultation{
		SchemaName:          domain.SchemaAgentConsultation,
		SchemaVersion:       domain.SchemaVersion,
		ConsultationID:      "consult-aaaaaaaaaaaaaaaaaaaaaaaa",
		CaseID:              view.Snapshot.Case.CaseID,
		RequestID:           requestID,
		RuntimeID:           "effexor-recovery-agent-runtime",
		RuntimeVersion:      "2.0.0",
		SourceCommitID:      view.CommitInfo.CommitID,
		InputDigest:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		GeneratedAt:         "2026-08-03T12:00:00Z",
		Status:              "completed",
		RoundCount:          1,
		FindingRefs:         findings,
		EvidenceRefs:        evidence,
		TargetRefs:          targets,
		Hypotheses:          []domain.AdvisoryHypothesis{},
		NextDiagnosticSteps: []string{},
		RetrievedSources:    []domain.RetrievedSource{},
		Limitations:         []string{"advisory only"},
		ProviderMetadata:    domain.ProviderMetadata{ProviderName: "mock"},
	}
}

func TestCommitAgentConsultationHappyPath(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	analyzed, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-ffffffffffffffffffffffff",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	reqID := "creq-aaaaaaaaaaaaaaaaaaaaaaaa"
	cons := sampleConsultation(analyzed.CaseView, reqID)
	res, err := c.CommitAgentConsultation(context.Background(), coordinator.CommitAgentConsultationRequest{
		CaseID:           analyzed.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CaseView.CommitInfo.CommitID,
		RequestID:        reqID,
		Consultation:     cons,
		Actor:            domain.ActorLLMAdvisor,
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
	if res.CaseView.Snapshot.WorkflowState.Revision != analyzed.CaseView.Snapshot.WorkflowState.Revision {
		t.Fatal("workflow revision must not change")
	}
	if len(res.CaseView.Snapshot.AgentConsultations) != 1 {
		t.Fatalf("consultations=%d", len(res.CaseView.Snapshot.AgentConsultations))
	}
	if len(res.CaseView.Snapshot.RepairPlans) != 0 {
		t.Fatal("repair plans must not be created")
	}
}

func TestCommitAgentConsultationIdempotent(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	analyzed, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-111111111111111111111111",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	reqID := "creq-bbbbbbbbbbbbbbbbbbbbbbbb"
	cons := sampleConsultation(analyzed.CaseView, reqID)
	req := coordinator.CommitAgentConsultationRequest{
		CaseID:           analyzed.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CaseView.CommitInfo.CommitID,
		RequestID:        reqID,
		Consultation:     cons,
		Actor:            domain.ActorSystem,
	}
	first, err := c.CommitAgentConsultation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.ExpectedCommitID = analyzed.CaseView.CommitInfo.CommitID // stale
	second, err := c.CommitAgentConsultation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Idempotent {
		t.Fatal("expected idempotent")
	}
	if second.CaseView.CommitInfo.CommitID != first.CaseView.CommitInfo.CommitID {
		t.Fatal("idempotent retry created new commit")
	}
}

func TestCommitAgentConsultationConflict(t *testing.T) {
	t.Parallel()
	c, view := bootDoctorReadyCase(t)
	analyzed, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-222222222222222222222222",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatal(err)
	}
	reqID := "creq-cccccccccccccccccccccccc"
	cons := sampleConsultation(analyzed.CaseView, reqID)
	_, err = c.CommitAgentConsultation(context.Background(), coordinator.CommitAgentConsultationRequest{
		CaseID:           analyzed.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID: analyzed.CaseView.CommitInfo.CommitID,
		RequestID:        reqID,
		Consultation:     cons,
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatal(err)
	}
	cons.Limitations = []string{"divergent payload"}
	loaded, err := c.LoadCase(context.Background(), analyzed.CaseView.Snapshot.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CommitAgentConsultation(context.Background(), coordinator.CommitAgentConsultationRequest{
		CaseID:           loaded.Snapshot.Case.CaseID,
		ExpectedCommitID: loaded.CommitInfo.CommitID,
		RequestID:        reqID,
		Consultation:     cons,
		Actor:            domain.ActorSystem,
	})
	if !errors.Is(err, coordinator.ErrAcquisitionConflict) {
		t.Fatalf("got %v", err)
	}
}
