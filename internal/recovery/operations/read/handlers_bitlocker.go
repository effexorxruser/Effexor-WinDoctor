package read

import (
	"context"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func handleInspectBitLockerInventory(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	volumes := make([]map[string]any, 0)
	ids := make([]string, 0)
	limitations := make([]string, 0)
	views := env.index.allBitLockerViews()
	if env.target.TargetType == "volume" {
		views = env.index.viewsForTarget(env.target.TargetID)
	}
	for _, view := range views {
		if view.EntityKind != "bitlocker_volume" {
			continue
		}
		payload, err := view.BitLocker()
		if err != nil {
			limitations = mergeLimitations(limitations, "bitlocker_payload_malformed")
			continue
		}
		ids = append(ids, view.Bundle.EvidenceID)
		limitations = mergeLimitations(limitations, view.Limitations...)
		volumes = append(volumes, map[string]any{
			"target_id":         view.Bundle.TargetID,
			"protection_status": payload.ProtectionStatus,
			"lock_status":       payload.LockStatus,
			"mount_point":       payload.MountPoint,
		})
	}
	if env.target.TargetType == "firmware" {
		for _, t := range env.index.byType["firmware"] {
			for _, lim := range t.Limitations {
				if strings.Contains(lim, "bitlocker") {
					limitations = mergeLimitations(limitations, lim)
				}
			}
		}
	}
	status := domain.ReadStatusOK
	if len(volumes) == 0 {
		status = domain.ReadStatusUnavailable
		limitations = mergeLimitations(limitations, "bitlocker_inventory_missing")
	}
	out := baseResult(env.request, domain.ObservationCaseSnapshot, status, sortedCopy(ids), mergeLimitations(limitations))
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{
		"anchor_target_id": env.target.TargetID,
		"volumes":          volumes,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}
