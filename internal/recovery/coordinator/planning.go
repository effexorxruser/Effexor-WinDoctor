package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/planner"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/policy"
)

// ProposeRepairPlanRequest asks the deterministic planner for a draft plan.
type ProposeRepairPlanRequest struct {
	CaseID           string
	ExpectedCommitID string
	RequestID        string
	Actor            domain.ActorType
	ReasonCode       string
}

// ProposeRepairPlanResult is the Case view after plan proposal.
type ProposeRepairPlanResult struct {
	CaseView   CaseView
	Plan       domain.RepairPlan
	Idempotent bool
}

// EvaluateRepairPlanPolicyRequest runs the independent policy engine.
type EvaluateRepairPlanPolicyRequest struct {
	CaseID           string
	ExpectedCommitID string
	RequestID        string
	Actor            domain.ActorType
	ReasonCode       string
}

// EvaluateRepairPlanPolicyResult is the Case view after policy evaluation.
type EvaluateRepairPlanPolicyResult struct {
	CaseView    CaseView
	Evaluation  domain.PolicyEvaluation
	Idempotent  bool
	StateChange bool
}

// ApproveRepairPlanRequest records explicit technician approval.
type ApproveRepairPlanRequest struct {
	CaseID            string
	ExpectedCommitID  string
	RequestID         string
	TechnicianRef     string
	AcknowledgedRisks []string
	ScopeSummary      string
	Actor             domain.ActorType
	ReasonCode        string
}

// ApproveRepairPlanResult is the Case view after approval.
type ApproveRepairPlanResult struct {
	CaseView   CaseView
	Approval   domain.RepairApproval
	Idempotent bool
}

// ProposeRepairPlan builds a draft RepairPlan and transitions analyzed -> plan_proposed.
func (c *Coordinator) ProposeRepairPlan(ctx context.Context, req ProposeRepairPlanRequest) (ProposeRepairPlanResult, error) {
	if err := ctx.Err(); err != nil {
		return ProposeRepairPlanResult{}, err
	}
	actor := defaultActor(req.Actor, domain.ActorSystem)
	if err := validatePlanRequestID(req.RequestID); err != nil {
		return ProposeRepairPlanResult{}, err
	}
	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return ProposeRepairPlanResult{}, err
	}
	if replay, err, ok := c.findPlanProposalReplay(snap, info, req.RequestID); ok {
		if err != nil {
			return ProposeRepairPlanResult{}, err
		}
		return replay, nil
	}
	if req.ExpectedCommitID == "" {
		return ProposeRepairPlanResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if req.ExpectedCommitID != info.CommitID {
		return ProposeRepairPlanResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}
	from := currentState(snap)
	if from != domain.WorkflowAnalyzed {
		return ProposeRepairPlanResult{}, &TransitionError{
			CaseID:  req.CaseID,
			From:    string(from),
			To:      string(domain.WorkflowPlanProposed),
			Reason:  "plan_not_allowed",
			Message: fmt.Sprintf("plan proposal requires workflow state analyzed (got %s)", from),
		}
	}

	result, err := planner.Plan(snap, info.CommitID)
	if err != nil {
		return ProposeRepairPlanResult{}, err
	}
	if result.Refusal != nil {
		return ProposeRepairPlanResult{}, &PlannerRefusalError{
			CaseID:  req.CaseID,
			Codes:   append([]string(nil), result.Refusal.Codes...),
			Message: result.Refusal.Message,
		}
	}
	plan := *result.Plan
	if plan.CaseID == "" {
		plan.CaseID = req.CaseID
	}
	if err := validatePlanForPR17(plan, req.CaseID); err != nil {
		return ProposeRepairPlanResult{}, err
	}

	next := copySnapshot(snap)
	mergedPlans, err := mergePlansImmutable(next.RepairPlans, plan)
	if err != nil {
		return ProposeRepairPlanResult{}, err
	}
	next.RepairPlans = mergedPlans
	to := domain.WorkflowPlanProposed
	if err := validateTransition(from, to, actor, len(next.Findings), len(next.RepairPlans)); err != nil {
		te, ok := err.(*TransitionError)
		if ok {
			te.CaseID = req.CaseID
		}
		return ProposeRepairPlanResult{}, err
	}
	revision := nextRevision(snap)
	reason := defaultReason(req.ReasonCode, "plan_committed")
	event, err := c.newAuditEvent(req.CaseID, domain.EventPlanCommitted, actor, from, to, info.CommitID, nil, reason, req.RequestID, revision)
	if err != nil {
		return ProposeRepairPlanResult{}, err
	}
	c.appendEvent(&next, event)
	if err := c.setWorkflow(&next, to, event.EventID, revision, nil, plan.PlanID); err != nil {
		return ProposeRepairPlanResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	stampAuditEvent(&next, event.EventID, planRefs(req.CaseID, plan), next.Case.UpdatedAt)
	if err := next.Validate(); err != nil {
		return ProposeRepairPlanResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	view, err := c.commitSnapshot(ctx, next, info.CommitID)
	if err != nil {
		return ProposeRepairPlanResult{}, err
	}
	return ProposeRepairPlanResult{CaseView: view, Plan: plan}, nil
}

// EvaluateRepairPlanPolicy evaluates the active plan. Allowed decisions advance to awaiting_approval.
func (c *Coordinator) EvaluateRepairPlanPolicy(ctx context.Context, req EvaluateRepairPlanPolicyRequest) (EvaluateRepairPlanPolicyResult, error) {
	if err := ctx.Err(); err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}
	actor := defaultActor(req.Actor, domain.ActorPolicy)
	if err := validatePolicyRequestID(req.RequestID); err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}
	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}
	if replay, err, ok := c.findPolicyEvaluationReplay(snap, info, req.RequestID); ok {
		if err != nil {
			return EvaluateRepairPlanPolicyResult{}, err
		}
		return replay, nil
	}
	if req.ExpectedCommitID == "" {
		return EvaluateRepairPlanPolicyResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if req.ExpectedCommitID != info.CommitID {
		return EvaluateRepairPlanPolicyResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}
	from := currentState(snap)
	if from != domain.WorkflowPlanProposed {
		return EvaluateRepairPlanPolicyResult{}, &TransitionError{
			CaseID:  req.CaseID,
			From:    string(from),
			To:      string(domain.WorkflowAwaitingApproval),
			Reason:  "policy_not_allowed",
			Message: fmt.Sprintf("policy evaluation requires workflow state plan_proposed (got %s)", from),
		}
	}
	plan, err := activePlan(snap)
	if err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}

	evaluation, err := policy.Evaluate(snap, *plan, info.CommitID, req.RequestID, c.clock.Now())
	if err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}
	next := copySnapshot(snap)
	if err := appendPolicyEvaluation(&next, evaluation); err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}
	stateChange := evaluation.Decision == "allowed"
	if stateChange {
		to := domain.WorkflowAwaitingApproval
		if err := validateTransition(from, to, actor, len(next.Findings), len(next.RepairPlans)); err != nil {
			te, ok := err.(*TransitionError)
			if ok {
				te.CaseID = req.CaseID
			}
			return EvaluateRepairPlanPolicyResult{}, err
		}
		revision := nextRevision(snap)
		reason := defaultReason(req.ReasonCode, "policy_evaluated")
		event, err := c.newAuditEvent(req.CaseID, domain.EventPolicyEvaluated, actor, from, to, info.CommitID, nil, reason, req.RequestID, revision)
		if err != nil {
			return EvaluateRepairPlanPolicyResult{}, err
		}
		c.appendEvent(&next, event)
		if err := c.setWorkflow(&next, to, event.EventID, revision, nil, plan.PlanID); err != nil {
			return EvaluateRepairPlanPolicyResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
		}
		stampAuditEvent(&next, event.EventID, policyRefs(req.CaseID, *plan, evaluation), next.Case.UpdatedAt)
	}
	if err := next.Validate(); err != nil {
		return EvaluateRepairPlanPolicyResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	view, err := c.commitSnapshot(ctx, next, info.CommitID)
	if err != nil {
		return EvaluateRepairPlanPolicyResult{}, err
	}
	return EvaluateRepairPlanPolicyResult{
		CaseView:    view,
		Evaluation:  evaluation,
		StateChange: stateChange,
	}, nil
}

// ApproveRepairPlan records technician approval and transitions awaiting_approval -> approved.
func (c *Coordinator) ApproveRepairPlan(ctx context.Context, req ApproveRepairPlanRequest) (ApproveRepairPlanResult, error) {
	if err := ctx.Err(); err != nil {
		return ApproveRepairPlanResult{}, err
	}
	actor := defaultActor(req.Actor, domain.ActorTechnician)
	if actor != domain.ActorTechnician {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: approval requires technician actor", ErrActorNotAllowed)
	}
	if err := validateApprovalRequestID(req.RequestID); err != nil {
		return ApproveRepairPlanResult{}, err
	}
	if req.TechnicianRef == "" {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: technician_ref is required", ErrInvalidArgument)
	}
	if req.ScopeSummary == "" {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: scope_summary is required", ErrInvalidArgument)
	}
	if len(req.AcknowledgedRisks) == 0 {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: acknowledged_risks is required", ErrInvalidArgument)
	}
	snap, info, err := c.loadLatestVerified(ctx, req.CaseID)
	if err != nil {
		return ApproveRepairPlanResult{}, err
	}
	plan, err := activePlan(snap)
	if err != nil {
		return ApproveRepairPlanResult{}, err
	}
	evaluation, err := latestAllowedEvaluation(snap, plan.PlanID)
	if err != nil {
		return ApproveRepairPlanResult{}, err
	}
	approval, err := buildRepairApproval(req, *plan, *evaluation, info.CommitID, c.clock.Now())
	if err != nil {
		return ApproveRepairPlanResult{}, err
	}
	if replay, err, ok := c.findApprovalReplay(snap, info, req.RequestID, approval, canonicalApprovalIdentity(approval)); ok {
		if err != nil {
			return ApproveRepairPlanResult{}, err
		}
		return replay, nil
	}
	if req.ExpectedCommitID == "" {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	if req.ExpectedCommitID != info.CommitID {
		return ApproveRepairPlanResult{}, &RevisionConflictError{
			CaseID:           req.CaseID,
			ExpectedCommitID: req.ExpectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}
	from := currentState(snap)
	if from != domain.WorkflowAwaitingApproval {
		return ApproveRepairPlanResult{}, &TransitionError{
			CaseID:  req.CaseID,
			From:    string(from),
			To:      string(domain.WorkflowApproved),
			Reason:  "approval_not_allowed",
			Message: fmt.Sprintf("approval requires workflow state awaiting_approval (got %s)", from),
		}
	}
	to := domain.WorkflowApproved
	if err := validateTransition(from, to, actor, len(snap.Findings), len(snap.RepairPlans)); err != nil {
		te, ok := err.(*TransitionError)
		if ok {
			te.CaseID = req.CaseID
		}
		return ApproveRepairPlanResult{}, err
	}
	next := copySnapshot(snap)
	if err := appendRepairApproval(&next, approval); err != nil {
		return ApproveRepairPlanResult{}, err
	}
	revision := nextRevision(snap)
	reason := defaultReason(req.ReasonCode, "approval_committed")
	event, err := c.newAuditEvent(req.CaseID, domain.EventApprovalCommitted, actor, from, to, info.CommitID, nil, reason, req.RequestID, revision)
	if err != nil {
		return ApproveRepairPlanResult{}, err
	}
	c.appendEvent(&next, event)
	if err := c.setWorkflow(&next, to, event.EventID, revision, nil, plan.PlanID); err != nil {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	stampAuditEvent(&next, event.EventID, approvalRefs(req.CaseID, *plan, *evaluation, approval), next.Case.UpdatedAt)
	if err := next.Validate(); err != nil {
		return ApproveRepairPlanResult{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	view, err := c.commitSnapshot(ctx, next, info.CommitID)
	if err != nil {
		return ApproveRepairPlanResult{}, err
	}
	return ApproveRepairPlanResult{CaseView: view, Approval: approval}, nil
}

func validatePlanRequestID(id string) error {
	return validatePrefixedRequestID(id, "planreq-")
}

func validatePolicyRequestID(id string) error {
	return validatePrefixedRequestID(id, "polreq-")
}

func validateApprovalRequestID(id string) error {
	return validatePrefixedRequestID(id, "apprreq-")
}

func validatePrefixedRequestID(id, prefix string) error {
	if id == "" {
		return fmt.Errorf("%w: request_id is required", ErrInvalidArgument)
	}
	if len(id) != len(prefix)+24 || id[:len(prefix)] != prefix {
		return fmt.Errorf("%w: request_id must match %s<24 lowercase hex>", ErrInvalidArgument, prefix)
	}
	for _, r := range id[len(prefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("%w: request_id must match %s<24 lowercase hex>", ErrInvalidArgument, prefix)
		}
	}
	return nil
}

func activePlan(snap casestore.Snapshot) (*domain.RepairPlan, error) {
	if snap.WorkflowState == nil || snap.WorkflowState.ActivePlanID == "" {
		return nil, fmt.Errorf("%w: active plan missing", ErrMissingDocument)
	}
	for i := range snap.RepairPlans {
		if snap.RepairPlans[i].PlanID == snap.WorkflowState.ActivePlanID {
			return &snap.RepairPlans[i], nil
		}
	}
	return nil, fmt.Errorf("%w: active plan %q not found", ErrMissingDocument, snap.WorkflowState.ActivePlanID)
}

func latestAllowedEvaluation(snap casestore.Snapshot, planID string) (*domain.PolicyEvaluation, error) {
	var latest *domain.PolicyEvaluation
	for i := range snap.PolicyEvaluations {
		pol := &snap.PolicyEvaluations[i]
		if pol.PlanID != planID || pol.Decision != "allowed" {
			continue
		}
		if latest == nil || pol.EvaluatedAt > latest.EvaluatedAt {
			latest = pol
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("%w: allowed policy evaluation missing for plan %q", ErrMissingDocument, planID)
	}
	return latest, nil
}

func buildRepairApproval(req ApproveRepairPlanRequest, plan domain.RepairPlan, evaluation domain.PolicyEvaluation, sourceCommitID string, now time.Time) (domain.RepairApproval, error) {
	planDigest, err := policy.DigestPlan(plan)
	if err != nil {
		return domain.RepairApproval{}, err
	}
	if evaluation.PlanDigest != planDigest {
		return domain.RepairApproval{}, fmt.Errorf("%w: policy evaluation plan_digest mismatch", ErrInvalidArgument)
	}
	policyDigest, err := policy.DigestEvaluation(evaluation)
	if err != nil {
		return domain.RepairApproval{}, err
	}
	input := fmt.Sprintf("approval|%s|%s|%s|%s|%s", req.CaseID, req.RequestID, plan.PlanID, planDigest, policyDigest)
	sum := sha256.Sum256([]byte(input))
	approval := domain.RepairApproval{
		SchemaName:        domain.SchemaRepairApproval,
		SchemaVersion:     domain.SchemaVersion,
		ApprovalID:        "appr-" + hex.EncodeToString(sum[:12]),
		CaseID:            req.CaseID,
		RequestID:         req.RequestID,
		PlanID:            plan.PlanID,
		PlanDigest:        planDigest,
		EvaluationID:      evaluation.EvaluationID,
		PolicyDigest:      policyDigest,
		SourceCommitID:    sourceCommitID,
		TopologyID:        evaluation.TopologyID,
		TechnicianRef:     req.TechnicianRef,
		ApprovedAt:        now.UTC().Format(time.RFC3339),
		Status:            "approved",
		AcknowledgedRisks: append([]string(nil), req.AcknowledgedRisks...),
		ScopeSummary:      req.ScopeSummary,
		Limitations: []string{
			"Approval does not execute repair operations.",
			"Backup and typed executor gates remain required before mutation.",
		},
	}
	if err := approval.Validate(); err != nil {
		return domain.RepairApproval{}, fmt.Errorf("%w: approval: %v", ErrInvalidArgument, err)
	}
	return approval, nil
}

func canonicalPolicyEvaluationBody(ev domain.PolicyEvaluation) ([]byte, error) {
	type identity struct {
		EvaluationID   string   `json:"evaluation_id"`
		CaseID         string   `json:"case_id"`
		RequestID      string   `json:"request_id"`
		PlanID         string   `json:"plan_id"`
		PlanDigest     string   `json:"plan_digest"`
		SourceCommitID string   `json:"source_commit_id"`
		Decision       string   `json:"decision"`
		ReasonCodes    []string `json:"reason_codes"`
		PolicyVersion  string   `json:"policy_version"`
		InputDigest    string   `json:"input_digest"`
	}
	payload := identity{
		EvaluationID: ev.EvaluationID, CaseID: ev.CaseID, RequestID: ev.RequestID,
		PlanID: ev.PlanID, PlanDigest: ev.PlanDigest, SourceCommitID: ev.SourceCommitID,
		Decision: ev.Decision, ReasonCodes: append([]string(nil), ev.ReasonCodes...),
		PolicyVersion: ev.PolicyVersion, InputDigest: ev.InputDigest,
	}
	return json.Marshal(payload)
}

func canonicalApprovalIdentity(a domain.RepairApproval) []byte {
	type identity struct {
		ApprovalID        string   `json:"approval_id"`
		CaseID            string   `json:"case_id"`
		RequestID         string   `json:"request_id"`
		PlanID            string   `json:"plan_id"`
		PlanDigest        string   `json:"plan_digest"`
		EvaluationID      string   `json:"evaluation_id"`
		PolicyDigest      string   `json:"policy_digest"`
		SourceCommitID    string   `json:"source_commit_id"`
		TechnicianRef     string   `json:"technician_ref"`
		Status            string   `json:"status"`
		AcknowledgedRisks []string `json:"acknowledged_risks"`
		ScopeSummary      string   `json:"scope_summary"`
	}
	payload := identity{
		ApprovalID: a.ApprovalID, CaseID: a.CaseID, RequestID: a.RequestID,
		PlanID: a.PlanID, PlanDigest: a.PlanDigest, EvaluationID: a.EvaluationID,
		PolicyDigest: a.PolicyDigest, SourceCommitID: a.SourceCommitID,
		TechnicianRef: a.TechnicianRef, Status: a.Status,
		AcknowledgedRisks: append([]string(nil), a.AcknowledgedRisks...),
		ScopeSummary:      a.ScopeSummary,
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func (c *Coordinator) findPlanProposalReplay(snap casestore.Snapshot, info casestore.CommitInfo, requestID string) (ProposeRepairPlanResult, error, bool) {
	for _, ev := range snap.CoordinatorEvents {
		if ev.EventType != domain.EventPlanCommitted || ev.CommandID != requestID {
			continue
		}
		var plan *domain.RepairPlan
		for i := range snap.RepairPlans {
			if containsCoordinatorRef(ev.ReferencedDocumentIDs, snap.RepairPlans[i].PlanID) {
				plan = &snap.RepairPlans[i]
				break
			}
		}
		if plan == nil {
			return ProposeRepairPlanResult{}, fmt.Errorf("%w: plan proposal replay missing plan", ErrInvalidArgument), true
		}
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return ProposeRepairPlanResult{}, err, true
		}
		return ProposeRepairPlanResult{CaseView: view, Plan: *plan, Idempotent: true}, nil, true
	}
	return ProposeRepairPlanResult{}, nil, false
}

func (c *Coordinator) findPolicyEvaluationReplay(snap casestore.Snapshot, info casestore.CommitInfo, requestID string) (EvaluateRepairPlanPolicyResult, error, bool) {
	for _, existing := range snap.PolicyEvaluations {
		if existing.RequestID != requestID {
			continue
		}
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return EvaluateRepairPlanPolicyResult{}, err, true
		}
		stateChange := existing.Decision == "allowed" && snap.WorkflowState != nil &&
			snap.WorkflowState.State == domain.WorkflowAwaitingApproval
		return EvaluateRepairPlanPolicyResult{
			CaseView:    view,
			Evaluation:  existing,
			Idempotent:  true,
			StateChange: stateChange,
		}, nil, true
	}
	return EvaluateRepairPlanPolicyResult{}, nil, false
}

func (c *Coordinator) findApprovalReplay(snap casestore.Snapshot, info casestore.CommitInfo, requestID string, want domain.RepairApproval, canonical []byte) (ApproveRepairPlanResult, error, bool) {
	for _, existing := range snap.RepairApprovals {
		if existing.RequestID != requestID && existing.ApprovalID != want.ApprovalID {
			continue
		}
		body := canonicalApprovalIdentity(existing)
		if existing.RequestID == requestID && !bytes.Equal(body, canonical) {
			return ApproveRepairPlanResult{}, &AcquisitionConflictError{
				CaseID:    snap.Case.CaseID,
				RequestID: requestID,
			}, true
		}
		if existing.ApprovalID == want.ApprovalID && !bytes.Equal(body, canonical) {
			return ApproveRepairPlanResult{}, &AcquisitionConflictError{
				CaseID:    snap.Case.CaseID,
				RequestID: requestID,
			}, true
		}
		if !bytes.Equal(body, canonical) {
			continue
		}
		view, err := c.viewFrom(snap, info)
		if err != nil {
			return ApproveRepairPlanResult{}, err, true
		}
		return ApproveRepairPlanResult{CaseView: view, Approval: existing, Idempotent: true}, nil, true
	}
	return ApproveRepairPlanResult{}, nil, false
}

func appendPolicyEvaluation(snap *casestore.Snapshot, ev domain.PolicyEvaluation) error {
	for _, existing := range snap.PolicyEvaluations {
		if existing.EvaluationID == ev.EvaluationID {
			return fmt.Errorf("%w: evaluation_id already exists", ErrInvalidArgument)
		}
		if existing.RequestID == ev.RequestID {
			return fmt.Errorf("%w: policy request_id already exists", ErrInvalidArgument)
		}
	}
	if err := ev.ValidatePolicyEvaluationRefs(buildCrossRefs(*snap)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	snap.PolicyEvaluations = append(snap.PolicyEvaluations, ev)
	return nil
}

func appendRepairApproval(snap *casestore.Snapshot, appr domain.RepairApproval) error {
	for _, existing := range snap.RepairApprovals {
		if existing.ApprovalID == appr.ApprovalID {
			return fmt.Errorf("%w: approval_id already exists", ErrInvalidArgument)
		}
		if existing.RequestID == appr.RequestID {
			return fmt.Errorf("%w: approval request_id already exists", ErrInvalidArgument)
		}
	}
	if err := appr.ValidateRepairApprovalRefs(buildCrossRefs(*snap)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	snap.RepairApprovals = append(snap.RepairApprovals, appr)
	return nil
}

func containsCoordinatorRef(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
