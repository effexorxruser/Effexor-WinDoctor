package read

import (
	"context"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func handleInspectFirmwareMode(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	views := env.index.viewsForTarget(env.target.TargetID)
	if len(views) == 0 {
		ids := env.index.evidenceIDsForTarget(env.target.TargetID)
		out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusUnavailable, ids, []string{"firmware_evidence_missing"})
		out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
		facts, err := marshalFacts(map[string]any{"firmware_mode": "unknown"})
		if err != nil {
			return domain.ReadOperationResult{}, err
		}
		out.Facts = facts
		return out, nil
	}
	mode := ""
	ids := make([]string, 0, len(views))
	limitations := make([]string, 0)
	for _, view := range views {
		ids = append(ids, view.Bundle.EvidenceID)
		fw, err := view.Firmware()
		if err != nil {
			limitations = append(limitations, "firmware_payload_malformed")
			continue
		}
		limitations = mergeLimitations(limitations, view.Limitations...)
		if fw.BootFirmwareMode != "" {
			if mode == "" {
				mode = strings.ToLower(fw.BootFirmwareMode)
			} else if mode != strings.ToLower(fw.BootFirmwareMode) {
				mode = "conflicting"
			}
		}
	}
	status := domain.ReadStatusOK
	if mode == "" || mode == "conflicting" {
		status = domain.ReadStatusPartial
		if mode == "" {
			mode = "unknown"
			limitations = mergeLimitations(limitations, "firmware_mode_absent")
		}
		if mode == "conflicting" {
			limitations = mergeLimitations(limitations, "firmware_mode_conflicting")
		}
	}
	out := baseResult(env.request, domain.ObservationCaseSnapshot, status, sortedCopy(ids), mergeLimitations(limitations))
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{"firmware_mode": mode})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}

func handleInspectBCDStore(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	views := env.index.viewsForTarget(env.target.TargetID)
	if len(views) == 0 {
		ids := env.index.evidenceIDsForTarget(env.target.TargetID)
		out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusUnavailable, ids, []string{"boot_store_evidence_missing"})
		out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
		facts, err := marshalFacts(map[string]any{"target_id": env.target.TargetID})
		if err != nil {
			return domain.ReadOperationResult{}, err
		}
		out.Facts = facts
		return out, nil
	}
	view := views[0]
	payload, err := view.BootStore()
	if err != nil {
		out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusPartial, []string{view.Bundle.EvidenceID},
			mergeLimitations(view.Limitations, "boot_store_payload_malformed"))
		out.ObservedAt = observedAtFromEvidence([]string{view.Bundle.EvidenceID}, env.index, env.request.Snapshot.Case.UpdatedAt)
		facts, mErr := marshalFacts(map[string]any{"target_id": env.target.TargetID})
		if mErr != nil {
			return domain.ReadOperationResult{}, mErr
		}
		out.Facts = facts
		return out, nil
	}
	ids := []string{view.Bundle.EvidenceID}
	out := baseResult(env.request, domain.ObservationCaseSnapshot, domain.ReadStatusOK, ids, view.Limitations)
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{
		"target_id": env.target.TargetID,
		"kind":      payload.Kind,
		"path":      payload.Path,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}

func handleInspectEFILayout(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	filterDisk := diskTargetID(env.params)
	if filterDisk != "" {
		if _, ok := env.index.targets[filterDisk]; !ok {
			return domain.ReadOperationResult{}, ErrTargetNotFound
		}
		if env.index.targets[filterDisk].TargetType != "disk" {
			return domain.ReadOperationResult{}, ErrUnsupportedTargetType
		}
	}
	entries := make([]map[string]any, 0)
	ids := make([]string, 0)
	limitations := make([]string, 0)
	for _, t := range env.index.byType["partition"] {
		if filterDisk != "" && !partitionOnDisk(env.index, t.TargetID, filterDisk, diskNumberForTarget(env.index, filterDisk)) {
			continue
		}
		for _, view := range env.index.viewsForTarget(t.TargetID) {
			if !isESPPayload(view) {
				continue
			}
			part, err := view.Partition()
			if err != nil {
				limitations = mergeLimitations(limitations, "partition_payload_malformed")
				continue
			}
			ids = append(ids, view.Bundle.EvidenceID)
			limitations = mergeLimitations(limitations, view.Limitations...)
			entry := map[string]any{
				"partition_target_id": t.TargetID,
				"gpt_type":            part.GPTType,
				"type":                part.Type,
			}
			if part.DiskNumber != nil {
				entry["disk_number"] = part.DiskNumber
			}
			entries = append(entries, entry)
		}
	}
	status := domain.ReadStatusOK
	if len(entries) == 0 {
		status = domain.ReadStatusUnavailable
		limitations = mergeLimitations(limitations, "esp_not_found")
	}
	out := baseResult(env.request, domain.ObservationCaseSnapshot, status, sortedCopy(ids), mergeLimitations(limitations))
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{
		"anchor_target_id": env.target.TargetID,
		"disk_target_id":   filterDisk,
		"esp_partitions":   entries,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}
