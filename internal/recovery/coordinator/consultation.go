package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// CommitAgentConsultationRequest appends an advisory AgentConsultation without
// advancing workflow past analyzed.
type CommitAgentConsultationRequest struct {
	CaseID           string
	ExpectedCommitID string
	RequestID        string
	Consultation     domain.AgentConsultation
	Actor            domain.ActorType
}

// CommitAgentConsultationResult is the Case view after consultation persistence.
type CommitAgentConsultationResult struct {
	CaseView     CaseView
	Consultation domain.AgentConsultation
	Idempotent   bool
}

// CommitAgentConsultation persists an immutable advisory consultation document.
// It does not emit CoordinatorEvents, create RepairPlans, mutate Findings, or
// change workflow state/revision.
func (c *Coordinator) CommitAgentConsultation(ctx context.Context, req CommitAgentConsultationRequest) (CommitAgentConsultationResult, error) {
	if err := ctx.Err(); err != nil {
		return CommitAgentConsultationResult{}, err
	}
	actor, err := requireConsultationActor(req.Actor)
	if err != nil {
		return CommitAgentConsultationResult{}, err
	}
	_ = actor
	if err := validateConsultationRequestID(req.RequestID); err != nil {
		return CommitAgentConsultationResult{}, err
	}
	if req.Consultation.RequestID != "" && req.Consultation.RequestID != req.RequestID {
		return CommitAgentConsultationResult{}, fmt.Errorf("%w: consultation.request_id must match request_id", ErrInvalidArgument)
	}
	cons := req.Consultation
	cons.RequestID = req.RequestID
	if cons.CaseID == "" {
		cons.CaseID = req.CaseID
	}
	if cons.CaseID != req.CaseID {
		return CommitAgentConsultationResult{}, fmt.Errorf("%w: consultation.case_id mismatch", ErrInvalidArgument)
	}

	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return CommitAgentConsultationResult{}, err
	}
	if err := requireAnalyzedForConsultation(snap, req.CaseID); err != nil {
		return CommitAgentConsultationResult{}, err
	}

	if cons.ConsultationID == "" {
		cons.ConsultationID = consultationIDFor(cons.CaseID, cons.RequestID, cons.InputDigest)
	}
	if cons.SourceCommitID == "" {
		cons.SourceCommitID = info.CommitID
	}

	canonical, err := canonicalConsultationBody(cons)
	if err != nil {
		return CommitAgentConsultationResult{}, err
	}
	if replay, err, ok := c.findConsultationReplay(snap, info, req.RequestID, cons.ConsultationID, canonical); ok {
		if err != nil {
			return CommitAgentConsultationResult{}, err
		}
		return replay, nil
	}

	if req.ExpectedCommitID == "" {
		return CommitAgentConsultationResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if req.ExpectedCommitID != info.CommitID {
		return CommitAgentConsultationResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}

	if err := cons.Validate(); err != nil {
		return CommitAgentConsultationResult{}, fmt.Errorf("%w: consultation: %v", ErrInvalidArgument, err)
	}

	next, err := appendConsultation(snap, cons)
	if err != nil {
		return CommitAgentConsultationResult{}, err
	}
	view, err := c.commitSnapshot(ctx, next, info.CommitID)
	if err != nil {
		return CommitAgentConsultationResult{}, err
	}
	return CommitAgentConsultationResult{
		CaseView:     view,
		Consultation: cons,
	}, nil
}

func requireConsultationActor(actor domain.ActorType) (domain.ActorType, error) {
	actor = defaultActor(actor, domain.ActorSystem)
	switch actor {
	case domain.ActorSystem, domain.ActorTechnician, domain.ActorLLMAdvisor:
		return actor, nil
	default:
		return "", fmt.Errorf("%w: actor_type %q", ErrActorNotAllowed, actor)
	}
}

func requireAnalyzedForConsultation(snap casestore.Snapshot, caseID string) error {
	state := currentState(snap)
	if state != domain.WorkflowAnalyzed {
		return &TransitionError{
			CaseID:  caseID,
			From:    string(state),
			To:      string(domain.WorkflowAnalyzed),
			Reason:  "consultation_not_allowed",
			Message: fmt.Sprintf("agent consultation requires workflow state analyzed (got %s)", state),
		}
	}
	return nil
}

func validateConsultationRequestID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidArgument)
	}
	matched := len(id) == len("creq-")+24
	if matched {
		for _, r := range id[len("creq-"):] {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				matched = false
				break
			}
		}
		if id[:len("creq-")] != "creq-" {
			matched = false
		}
	}
	if !matched {
		return fmt.Errorf("%w: request_id must match creq-<24 lowercase hex>", ErrInvalidArgument)
	}
	return nil
}

func consultationIDFor(caseID, requestID, inputDigest string) string {
	sum := sha256.Sum256([]byte("agentruntime|consultation|" + caseID + "|" + requestID + "|" + inputDigest))
	return "consult-" + hex.EncodeToString(sum[:12])
}

func canonicalConsultationBody(cons domain.AgentConsultation) ([]byte, error) {
	// Identity ignores generated_at so retries with a new wall clock match.
	type identity struct {
		SchemaName           string                      `json:"schema_name"`
		SchemaVersion        string                      `json:"schema_version"`
		ConsultationID       string                      `json:"consultation_id"`
		CaseID               string                      `json:"case_id"`
		RequestID            string                      `json:"request_id"`
		RuntimeID            string                      `json:"runtime_id"`
		RuntimeVersion       string                      `json:"runtime_version"`
		SourceCommitID       string                      `json:"source_commit_id"`
		InputDigest          string                      `json:"input_digest"`
		Status               string                      `json:"status"`
		RoundCount           int                         `json:"round_count"`
		TopologyID           string                      `json:"topology_id,omitempty"`
		FindingRefs          []string                    `json:"finding_refs"`
		EvidenceRefs         []string                    `json:"evidence_refs"`
		TargetRefs           []string                    `json:"target_refs"`
		Hypotheses           []domain.AdvisoryHypothesis `json:"hypotheses"`
		NextDiagnosticSteps  []string                    `json:"next_diagnostic_steps"`
		RetrievedSources     []domain.RetrievedSource    `json:"retrieved_sources"`
		Limitations          []string                    `json:"limitations"`
		ProviderMetadata     domain.ProviderMetadata     `json:"provider_metadata"`
		InsufficientEvidence bool                        `json:"insufficient_evidence,omitempty"`
	}
	payload := identity{
		SchemaName:           cons.SchemaName,
		SchemaVersion:        cons.SchemaVersion,
		ConsultationID:       cons.ConsultationID,
		CaseID:               cons.CaseID,
		RequestID:            cons.RequestID,
		RuntimeID:            cons.RuntimeID,
		RuntimeVersion:       cons.RuntimeVersion,
		SourceCommitID:       cons.SourceCommitID,
		InputDigest:          cons.InputDigest,
		Status:               cons.Status,
		RoundCount:           cons.RoundCount,
		TopologyID:           cons.TopologyID,
		FindingRefs:          cons.FindingRefs,
		EvidenceRefs:         cons.EvidenceRefs,
		TargetRefs:           cons.TargetRefs,
		Hypotheses:           cons.Hypotheses,
		NextDiagnosticSteps:  cons.NextDiagnosticSteps,
		RetrievedSources:     cons.RetrievedSources,
		Limitations:          cons.Limitations,
		ProviderMetadata:     cons.ProviderMetadata,
		InsufficientEvidence: cons.InsufficientEvidence,
	}
	return json.Marshal(payload)
}

func consultationsCanonicallyEqual(a, b domain.AgentConsultation) bool {
	left, err := canonicalConsultationBody(a)
	if err != nil {
		return false
	}
	right, err := canonicalConsultationBody(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}

func (c *Coordinator) findConsultationReplay(
	snap casestore.Snapshot,
	info casestore.CommitInfo,
	requestID, consultationID string,
	canonical []byte,
) (CommitAgentConsultationResult, error, bool) {
	for _, existing := range snap.AgentConsultations {
		if existing.RequestID != requestID && existing.ConsultationID != consultationID {
			continue
		}
		body, err := canonicalConsultationBody(existing)
		if err != nil {
			return CommitAgentConsultationResult{}, err, true
		}
		if existing.RequestID == requestID && !bytes.Equal(body, canonical) {
			return CommitAgentConsultationResult{}, &AcquisitionConflictError{
				CaseID:    snap.Case.CaseID,
				RequestID: requestID,
			}, true
		}
		if existing.ConsultationID == consultationID && !bytes.Equal(body, canonical) {
			return CommitAgentConsultationResult{}, &AcquisitionConflictError{
				CaseID:    snap.Case.CaseID,
				RequestID: requestID,
			}, true
		}
		if !bytes.Equal(body, canonical) {
			continue
		}
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return CommitAgentConsultationResult{}, err, true
		}
		return CommitAgentConsultationResult{
			CaseView:     view,
			Consultation: existing,
			Idempotent:   true,
		}, nil, true
	}
	return CommitAgentConsultationResult{}, nil, false
}

func appendConsultation(snap casestore.Snapshot, cons domain.AgentConsultation) (casestore.Snapshot, error) {
	next := copySnapshot(snap)
	for _, existing := range next.AgentConsultations {
		if existing.ConsultationID == cons.ConsultationID {
			return casestore.Snapshot{}, fmt.Errorf("%w: consultation_id already exists", ErrInvalidArgument)
		}
		if existing.RequestID == cons.RequestID {
			return casestore.Snapshot{}, fmt.Errorf("%w: consultation request_id already exists", ErrInvalidArgument)
		}
	}
	if err := cons.ValidateConsultationRefs(buildCrossRefs(next)); err != nil {
		return casestore.Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	next.AgentConsultations = append(next.AgentConsultations, cons)
	if err := next.Validate(); err != nil {
		return casestore.Snapshot{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return next, nil
}

func buildCrossRefs(s casestore.Snapshot) domain.CrossRefs {
	targetIDs := make(map[string]struct{}, len(s.Targets))
	for _, t := range s.Targets {
		targetIDs[t.TargetID] = struct{}{}
	}
	evidenceIDs := make(map[string]struct{}, len(s.EvidenceBundles))
	for _, e := range s.EvidenceBundles {
		evidenceIDs[e.EvidenceID] = struct{}{}
	}
	findingIDs := make(map[string]struct{}, len(s.Findings))
	for _, f := range s.Findings {
		findingIDs[f.FindingID] = struct{}{}
	}
	planIDs := make(map[string]struct{}, len(s.RepairPlans))
	for _, p := range s.RepairPlans {
		planIDs[p.PlanID] = struct{}{}
	}
	executionIDs := make(map[string]struct{}, len(s.ExecutionEvents))
	for _, e := range s.ExecutionEvents {
		executionIDs[e.ExecutionID] = struct{}{}
	}
	verificationIDs := make(map[string]struct{}, len(s.VerificationReports))
	for _, v := range s.VerificationReports {
		verificationIDs[v.VerificationID] = struct{}{}
	}
	eventIDs := make(map[string]struct{}, len(s.CoordinatorEvents))
	for _, ev := range s.CoordinatorEvents {
		eventIDs[ev.EventID] = struct{}{}
	}
	docIDs := map[string]struct{}{s.Case.CaseID: {}}
	for id := range targetIDs {
		docIDs[id] = struct{}{}
	}
	for id := range evidenceIDs {
		docIDs[id] = struct{}{}
	}
	for id := range findingIDs {
		docIDs[id] = struct{}{}
	}
	for id := range planIDs {
		docIDs[id] = struct{}{}
	}
	for id := range executionIDs {
		docIDs[id] = struct{}{}
	}
	for id := range verificationIDs {
		docIDs[id] = struct{}{}
	}
	for id := range eventIDs {
		docIDs[id] = struct{}{}
	}
	policyIDs := make(map[string]struct{}, len(s.PolicyEvaluations))
	for _, pol := range s.PolicyEvaluations {
		policyIDs[pol.EvaluationID] = struct{}{}
	}
	approvalIDs := make(map[string]struct{}, len(s.RepairApprovals))
	for _, appr := range s.RepairApprovals {
		approvalIDs[appr.ApprovalID] = struct{}{}
	}
	for id := range policyIDs {
		docIDs[id] = struct{}{}
	}
	for id := range approvalIDs {
		docIDs[id] = struct{}{}
	}
	if s.WorkflowState != nil {
		docIDs[domain.DocumentIDCaseWorkflowState] = struct{}{}
	}
	return domain.CrossRefs{
		CaseIDs:             map[string]struct{}{s.Case.CaseID: {}},
		TargetIDs:           targetIDs,
		EvidenceIDs:         evidenceIDs,
		FindingIDs:          findingIDs,
		PlanIDs:             planIDs,
		ExecutionIDs:        executionIDs,
		VerificationIDs:     verificationIDs,
		CoordinatorEventIDs: eventIDs,
		PolicyEvaluationIDs: policyIDs,
		RepairApprovalIDs:   approvalIDs,
		DocumentIDs:         docIDs,
	}
}
