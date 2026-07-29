package coordinator

import (
	"context"
	"errors"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func (c *Coordinator) loadExpected(ctx context.Context, caseID, expectedCommitID string) (casestore.Snapshot, casestore.CommitInfo, error) {
	if caseID == "" {
		return casestore.Snapshot{}, casestore.CommitInfo{}, fmt.Errorf("%w: case_id is required", ErrInvalidArgument)
	}
	if expectedCommitID == "" {
		return casestore.Snapshot{}, casestore.CommitInfo{}, fmt.Errorf("%w: expected_commit_id is required", ErrInvalidArgument)
	}
	report, err := c.store.Verify(ctx, caseID)
	if err != nil {
		if isIntegrityFailure(err) {
			return casestore.Snapshot{}, casestore.CommitInfo{}, fmt.Errorf("%w: %v", ErrCaseCorrupt, err)
		}
		return casestore.Snapshot{}, casestore.CommitInfo{}, err
	}
	if report.Status == casestore.IntegrityCorrupt {
		return casestore.Snapshot{}, casestore.CommitInfo{}, fmt.Errorf("%w: verify status corrupt for case %s", ErrCaseCorrupt, caseID)
	}
	snap, info, err := c.store.LoadLatest(ctx, caseID)
	if err != nil {
		if isIntegrityFailure(err) {
			return casestore.Snapshot{}, casestore.CommitInfo{}, fmt.Errorf("%w: %v", ErrCaseCorrupt, err)
		}
		return casestore.Snapshot{}, casestore.CommitInfo{}, err
	}
	if info.CommitID != expectedCommitID {
		return casestore.Snapshot{}, casestore.CommitInfo{}, &RevisionConflictError{
			CaseID:           caseID,
			ExpectedCommitID: expectedCommitID,
			ActualCommitID:   info.CommitID,
		}
	}
	return snap, info, nil
}

func (c *Coordinator) commitSnapshot(ctx context.Context, snap casestore.Snapshot, expectedParentCommitID string) (CaseView, error) {
	info, err := c.store.Commit(ctx, casestore.CommitRequest{
		Snapshot:               snap,
		Reason:                 casestore.CommitReasonCaseSnapshot,
		ExpectedParentCommitID: expectedParentCommitID,
	})
	if err != nil {
		if errors.Is(err, casestore.ErrRevisionConflict) {
			actual := ""
			if loaded, latest, loadErr := c.store.LoadLatest(ctx, snap.Case.CaseID); loadErr == nil {
				actual = latest.CommitID
				_ = loaded
			}
			return CaseView{}, &RevisionConflictError{
				CaseID:           snap.Case.CaseID,
				ExpectedCommitID: expectedParentCommitID,
				ActualCommitID:   actual,
			}
		}
		return CaseView{}, err
	}
	loaded, info2, err := c.store.LoadLatest(ctx, snap.Case.CaseID)
	if err != nil {
		return CaseView{}, err
	}
	_ = info
	return c.viewFrom(loaded, info2)
}

// CommitAnalysis persists Findings and transitions to analyzed.
func (c *Coordinator) CommitAnalysis(ctx context.Context, req CommitAnalysisRequest) (CaseView, error) {
	actor := defaultActor(req.Actor, domain.ActorDeterministicAnalyzer)
	reason := defaultReason(req.ReasonCode, "analysis_committed")
	snap, info, err := c.loadExpected(ctx, req.CaseID, req.ExpectedCommitID)
	if err != nil {
		return CaseView{}, err
	}
	from := currentState(snap)
	to := domain.WorkflowAnalyzed
	if err := validateTransition(from, to, actor, len(req.Findings), len(snap.RepairPlans)); err != nil {
		te, ok := err.(*TransitionError)
		if ok {
			te.CaseID = req.CaseID
		}
		return CaseView{}, err
	}

	next := copySnapshot(snap)
	next.Findings = append([]domain.Finding(nil), req.Findings...)
	refs := make([]string, 0, len(req.Findings))
	for _, f := range req.Findings {
		if f.CaseID == "" {
			f.CaseID = req.CaseID
		}
		refs = append(refs, f.FindingID)
	}
	// Re-assign with case_id filled when callers omit it.
	filled := make([]domain.Finding, len(req.Findings))
	for i, f := range req.Findings {
		if f.CaseID == "" {
			f.CaseID = req.CaseID
		}
		filled[i] = f
		refs[i] = f.FindingID
	}
	next.Findings = filled

	event, err := c.newAuditEvent(
		req.CaseID,
		domain.EventAnalysisCommitted,
		actor,
		from,
		to,
		info.CommitID,
		refs,
		reason,
		req.CommandID,
	)
	if err != nil {
		return CaseView{}, err
	}
	c.appendEvent(&next, event)
	activePlan := ""
	if next.WorkflowState != nil {
		activePlan = next.WorkflowState.ActivePlanID
	}
	c.setWorkflow(&next, to, event.EventID, nextRevision(snap), nil, activePlan)

	if err := next.Validate(); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return c.commitSnapshot(ctx, next, info.CommitID)
}

// CommitPlan persists a RepairPlan and transitions analyzed -> plan_proposed.
func (c *Coordinator) CommitPlan(ctx context.Context, req CommitPlanRequest) (CaseView, error) {
	actor := defaultActor(req.Actor, domain.ActorSystem)
	reason := defaultReason(req.ReasonCode, "plan_committed")
	snap, info, err := c.loadExpected(ctx, req.CaseID, req.ExpectedCommitID)
	if err != nil {
		return CaseView{}, err
	}
	from := currentState(snap)
	to := domain.WorkflowPlanProposed

	plan := req.Plan
	if plan.CaseID == "" {
		plan.CaseID = req.CaseID
	}
	next := copySnapshot(snap)
	// Upsert by plan_id.
	replaced := false
	for i, p := range next.RepairPlans {
		if p.PlanID == plan.PlanID {
			next.RepairPlans[i] = plan
			replaced = true
			break
		}
	}
	if !replaced {
		next.RepairPlans = append(next.RepairPlans, plan)
	}

	if err := validateTransition(from, to, actor, len(next.Findings), len(next.RepairPlans)); err != nil {
		te, ok := err.(*TransitionError)
		if ok {
			te.CaseID = req.CaseID
		}
		return CaseView{}, err
	}

	event, err := c.newAuditEvent(
		req.CaseID,
		domain.EventPlanCommitted,
		actor,
		from,
		to,
		info.CommitID,
		[]string{plan.PlanID},
		reason,
		req.CommandID,
	)
	if err != nil {
		return CaseView{}, err
	}
	c.appendEvent(&next, event)
	c.setWorkflow(&next, to, event.EventID, nextRevision(snap), nil, plan.PlanID)

	if err := next.Validate(); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return c.commitSnapshot(ctx, next, info.CommitID)
}

// FailCase transitions the Case to failed.
func (c *Coordinator) FailCase(ctx context.Context, req FailCaseRequest) (CaseView, error) {
	actor := defaultActor(req.Actor, domain.ActorTechnician)
	reason := defaultReason(req.ReasonCode, "case_failed")
	snap, info, err := c.loadExpected(ctx, req.CaseID, req.ExpectedCommitID)
	if err != nil {
		return CaseView{}, err
	}
	from := currentState(snap)
	to := domain.WorkflowFailed
	if err := validateTransition(from, to, actor, len(snap.Findings), len(snap.RepairPlans)); err != nil {
		te, ok := err.(*TransitionError)
		if ok {
			te.CaseID = req.CaseID
		}
		return CaseView{}, err
	}
	next := copySnapshot(snap)
	event, err := c.newAuditEvent(
		req.CaseID,
		domain.EventCaseFailed,
		actor,
		from,
		to,
		info.CommitID,
		[]string{req.CaseID},
		reason,
		req.CommandID,
	)
	if err != nil {
		return CaseView{}, err
	}
	c.appendEvent(&next, event)
	failure := &domain.WorkflowFailure{ReasonCode: reason, DetailCode: req.DetailCode}
	activePlan := ""
	if next.WorkflowState != nil {
		activePlan = next.WorkflowState.ActivePlanID
	}
	c.setWorkflow(&next, to, event.EventID, nextRevision(snap), failure, activePlan)
	if err := next.Validate(); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return c.commitSnapshot(ctx, next, info.CommitID)
}

// CancelCase transitions the Case to cancelled.
func (c *Coordinator) CancelCase(ctx context.Context, req CancelCaseRequest) (CaseView, error) {
	actor := defaultActor(req.Actor, domain.ActorTechnician)
	reason := defaultReason(req.ReasonCode, "case_cancelled")
	snap, info, err := c.loadExpected(ctx, req.CaseID, req.ExpectedCommitID)
	if err != nil {
		return CaseView{}, err
	}
	from := currentState(snap)
	to := domain.WorkflowCancelled
	if err := validateTransition(from, to, actor, len(snap.Findings), len(snap.RepairPlans)); err != nil {
		te, ok := err.(*TransitionError)
		if ok {
			te.CaseID = req.CaseID
		}
		return CaseView{}, err
	}
	next := copySnapshot(snap)
	event, err := c.newAuditEvent(
		req.CaseID,
		domain.EventCaseCancelled,
		actor,
		from,
		to,
		info.CommitID,
		[]string{req.CaseID},
		reason,
		req.CommandID,
	)
	if err != nil {
		return CaseView{}, err
	}
	c.appendEvent(&next, event)
	activePlan := ""
	if next.WorkflowState != nil {
		activePlan = next.WorkflowState.ActivePlanID
	}
	c.setWorkflow(&next, to, event.EventID, nextRevision(snap), nil, activePlan)
	if err := next.Validate(); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return c.commitSnapshot(ctx, next, info.CommitID)
}
