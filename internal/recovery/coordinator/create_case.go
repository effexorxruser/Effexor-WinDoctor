package coordinator

import (
	"context"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

// CreateCase imports a diagnostic-report and commits the initial Case snapshot.
// It requires that no Case head exists (create-only). A second CreateCase for
// the same report hash returns ErrCaseAlreadyExists and does not append state.
func (c *Coordinator) CreateCase(ctx context.Context, req CreateCaseRequest) (CaseView, error) {
	if len(req.DiagnosticReport) == 0 {
		return CaseView{}, fmt.Errorf("%w: diagnostic report is required", ErrInvalidArgument)
	}
	actor := defaultActor(req.Actor, domain.ActorSystem)
	reason := defaultReason(req.ReasonCode, "legacy_import_committed")
	if _, ok := allowedPR17Actors[actor]; !ok {
		return CaseView{}, &TransitionError{Reason: "actor_not_allowed", Message: fmt.Sprintf("actor %s is not permitted", actor)}
	}

	result, err := c.importer.ImportJSON(req.DiagnosticReport, legacyreport.Options{SourceArtifact: req.SourceArtifact})
	if err != nil {
		return CaseView{}, fmt.Errorf("%w: import: %v", ErrInvalidArgument, err)
	}

	snap := casestore.SnapshotFromImporterResult(result)
	snap.Normalize()

	if err := validateTransition(domain.WorkflowCreated, domain.WorkflowEvidenceCollected, actor, 0, 0); err != nil {
		return CaseView{}, err
	}

	const revision uint64 = 1
	event, err := c.newAuditEvent(
		snap.Case.CaseID,
		domain.EventCaseCreated,
		actor,
		domain.WorkflowCreated,
		domain.WorkflowEvidenceCollected,
		"",
		nil,
		reason,
		req.CommandID,
		revision,
	)
	if err != nil {
		return CaseView{}, err
	}
	c.appendEvent(&snap, event)
	if err := c.setWorkflow(&snap, domain.WorkflowEvidenceCollected, event.EventID, revision, nil, ""); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	stampAuditEvent(&snap, event.EventID, createOrAdoptRefs(snap), snap.Case.UpdatedAt)

	if err := snap.Validate(); err != nil {
		return CaseView{}, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	snap.Normalize()
	info, err := c.store.Commit(ctx, casestore.CommitRequest{
		Snapshot:          snap,
		ArtifactProvider:  req.ArtifactProvider,
		Reason:            casestore.CommitReasonLegacyImport,
		ParentExpectation: casestore.ExpectAbsentParent(),
	})
	if err != nil {
		return CaseView{}, mapStoreWriteError(ctx, c, snap.Case.CaseID, "", err)
	}
	return c.viewFrom(snap, info)
}
