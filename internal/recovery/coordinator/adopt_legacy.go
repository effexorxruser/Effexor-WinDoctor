package coordinator

import (
	"context"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// AdoptLegacyCaseRequest adopts a legacy Case Store snapshot that has no workflow state.
type AdoptLegacyCaseRequest struct {
	CaseID           string
	ExpectedCommitID string
	Actor            domain.ActorType
	ReasonCode       string
	CommandID        string
}

// AdoptLegacyCase attaches case-workflow-state to a legacy snapshot that already
// has Case/Targets/Evidence but no WorkflowState. LoadCase remains read-only;
// CreateCase is never used as a migration path.
func (c *Coordinator) AdoptLegacyCase(ctx context.Context, req AdoptLegacyCaseRequest) (CaseView, error) {
	actor := defaultActor(req.Actor, domain.ActorSystem)
	reason := defaultReason(req.ReasonCode, "legacy_case_adopted")
	if _, ok := allowedPR17Actors[actor]; !ok {
		return CaseView{}, &TransitionError{Reason: "actor_not_allowed", Message: fmt.Sprintf("actor %s is not permitted", actor)}
	}

	snap, info, err := c.loadExpected(ctx, req.CaseID, req.ExpectedCommitID)
	if err != nil {
		return CaseView{}, err
	}
	if snap.WorkflowState != nil {
		return CaseView{}, fmt.Errorf("%w: workflow state already present", ErrLegacyAdoptionRejected)
	}
	if len(snap.Findings) > 0 || len(snap.RepairPlans) > 0 ||
		len(snap.ExecutionEvents) > 0 || len(snap.VerificationReports) > 0 {
		return CaseView{}, fmt.Errorf("%w: legacy snapshot contains later lifecycle documents", ErrLegacyAdoptionRejected)
	}
	if len(snap.Targets) == 0 || len(snap.EvidenceBundles) == 0 {
		return CaseView{}, fmt.Errorf("%w: legacy snapshot missing targets or evidence", ErrLegacyAdoptionRejected)
	}

	next := copySnapshot(snap)
	event, err := c.newAuditEvent(
		req.CaseID,
		domain.EventLegacyCaseAdopted,
		actor,
		"",
		domain.WorkflowEvidenceCollected,
		info.CommitID,
		nil,
		reason,
		req.CommandID,
	)
	if err != nil {
		return CaseView{}, err
	}
	// Clear PreviousState for adoption (omit empty).
	event.PreviousState = ""
	c.appendEvent(&next, event)
	if err := c.setWorkflow(&next, domain.WorkflowEvidenceCollected, event.EventID, 1, nil, ""); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	for i := range next.CoordinatorEvents {
		if next.CoordinatorEvents[i].EventID == event.EventID {
			next.CoordinatorEvents[i].ReferencedDocumentIDs = fullDocumentRefs(next)
			next.CoordinatorEvents[i].OccurredAt = next.Case.UpdatedAt
			next.CoordinatorEvents[i].PreviousState = ""
			break
		}
	}
	if err := next.Validate(); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	return c.commitSnapshot(ctx, next, info.CommitID)
}
