package read

import (
	"context"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func handleInspectWindowsInstallation(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	evidenceIDs := env.index.evidenceIDsForTarget(env.target.TargetID)
	views := env.index.viewsForTarget(env.target.TargetID)
	if len(views) == 0 {
		out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusUnavailable, evidenceIDs, []string{"windows_installation_evidence_missing"})
		out.ObservedAt = observedAtFromEvidence(evidenceIDs, env.index, env.request.Snapshot.Case.UpdatedAt)
		facts, err := marshalFacts(map[string]any{"target_id": env.target.TargetID})
		if err != nil {
			return domain.ReadOperationResult{}, err
		}
		out.Facts = facts
		return out, nil
	}
	view := views[0]
	payload, err := view.WindowsInstallation()
	if err != nil {
		out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusPartial, []string{view.Bundle.EvidenceID},
			mergeLimitations(view.Limitations, "windows_installation_payload_malformed"))
		out.ObservedAt = observedAtFromEvidence([]string{view.Bundle.EvidenceID}, env.index, env.request.Snapshot.Case.UpdatedAt)
		facts, mErr := marshalFacts(map[string]any{"target_id": env.target.TargetID})
		if mErr != nil {
			return domain.ReadOperationResult{}, mErr
		}
		out.Facts = facts
		return out, nil
	}
	ids := sortedCopy([]string{view.Bundle.EvidenceID})
	out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusOK, ids, view.Limitations)
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{
		"target_id":    env.target.TargetID,
		"root_path":    payload.RootPath,
		"version":      payload.Version,
		"display_name": env.target.DisplayName,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}
