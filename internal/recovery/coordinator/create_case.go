package coordinator

import (
	"context"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

// CreateCase imports a diagnostic-report and commits the initial Case snapshot.
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

	event, err := c.newAuditEvent(
		snap.Case.CaseID,
		domain.EventCaseCreated,
		actor,
		domain.WorkflowCreated,
		domain.WorkflowEvidenceCollected,
		"",
		append([]string{snap.Case.CaseID}, snap.Case.TargetIDs...),
		reason,
		req.CommandID,
	)
	if err != nil {
		return CaseView{}, err
	}
	if err := validateTransition(domain.WorkflowCreated, domain.WorkflowEvidenceCollected, actor, 0, 0); err != nil {
		return CaseView{}, err
	}
	c.appendEvent(&snap, event)
	c.setWorkflow(&snap, domain.WorkflowEvidenceCollected, event.EventID, 1, nil, "")

	info, err := c.store.Commit(ctx, casestore.CommitRequest{
		Snapshot:         snap,
		ArtifactProvider: req.ArtifactProvider,
		Reason:           casestore.CommitReasonLegacyImport,
	})
	if err != nil {
		return CaseView{}, err
	}

	// Reload to return store-normalized view and fill resulting ids on a follow-up
	// only when needed; resulting commit ids stay on CommitInfo for PR #17.
	loaded, info2, err := c.store.LoadLatest(ctx, snap.Case.CaseID)
	if err != nil {
		return CaseView{}, err
	}
	_ = info
	return c.viewFrom(loaded, info2)
}
