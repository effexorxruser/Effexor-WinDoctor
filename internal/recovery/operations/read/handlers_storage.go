package read

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func handleInspectDiskHealth(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	diskNumber := diskNumberForTarget(env.index, env.target.TargetID)
	records := make([]map[string]any, 0)
	ids := make([]string, 0)
	limitations := make([]string, 0)
	for _, view := range env.index.viewsForTarget(env.target.TargetID) {
		ids = append(ids, view.Bundle.EvidenceID)
	}
	for _, view := range env.index.views {
		if view.EntityKind != "firmware_environment" {
			continue
		}
		driveHealth, err := view.DriveHealthRecords()
		if err != nil {
			limitations = mergeLimitations(limitations, "drive_health_malformed")
			continue
		}
		ids = append(ids, view.Bundle.EvidenceID)
		for _, rec := range driveHealth {
			if diskNumber != nil && !driveHealthMatchesDisk(rec, *diskNumber) {
				continue
			}
			records = append(records, rec)
		}
	}
	status := domain.ReadStatusOK
	if len(records) == 0 {
		status = domain.ReadStatusUnavailable
		limitations = mergeLimitations(limitations, "disk_health_missing")
	}
	out := baseResult(env.request, domain.ObservationCaseSnapshot, status, sortedCopy(ids), mergeLimitations(limitations))
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{
		"disk_target_id": env.target.TargetID,
		"drive_health":   records,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}

func handleInspectPartitionLayout(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
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
	partitions := make([]map[string]any, 0)
	ids := make([]string, 0)
	limitations := make([]string, 0)
	targetPartitions := env.index.byType["partition"]
	if env.target.TargetType == "disk" {
		targetPartitions = env.index.partitionsOnDisk(env.target.TargetID)
	}
	for _, t := range targetPartitions {
		if filterDisk != "" && !partitionOnDisk(env.index, t.TargetID, filterDisk, diskNumberForTarget(env.index, filterDisk)) {
			continue
		}
		if env.target.TargetType == "disk" && !partitionOnDisk(env.index, t.TargetID, env.target.TargetID, diskNumberForTarget(env.index, env.target.TargetID)) {
			continue
		}
		for _, view := range env.index.viewsForTarget(t.TargetID) {
			part, err := view.Partition()
			if err != nil {
				limitations = mergeLimitations(limitations, "partition_payload_malformed")
				continue
			}
			ids = append(ids, view.Bundle.EvidenceID)
			limitations = mergeLimitations(limitations, view.Limitations...)
			entry := map[string]any{
				"partition_target_id": t.TargetID,
				"display_name":        t.DisplayName,
				"type":                part.Type,
				"gpt_type":            part.GPTType,
				"drive_letter":        part.DriveLetter,
			}
			if part.DiskNumber != nil {
				entry["disk_number"] = part.DiskNumber
			}
			partitions = append(partitions, entry)
		}
	}
	status := domain.ReadStatusOK
	if len(partitions) == 0 {
		status = domain.ReadStatusUnavailable
		limitations = mergeLimitations(limitations, "partition_layout_missing")
	}
	out := baseResult(env.request, domain.ObservationCaseSnapshot, status, sortedCopy(ids), mergeLimitations(limitations))
	out.ObservedAt = observedAtFromEvidence(ids, env.index, env.request.Snapshot.Case.UpdatedAt)
	facts, err := marshalFacts(map[string]any{
		"anchor_target_id": env.target.TargetID,
		"disk_target_id":   filterDisk,
		"partitions":       partitions,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}

func driveHealthMatchesDisk(record map[string]any, diskNumber int64) bool {
	if id, ok := record["device_id"].(string); ok {
		var n int64
		if _, err := fmt.Sscan(id, &n); err == nil && n == diskNumber {
			return true
		}
	}
	if n, ok := asInt64(record["disk_number"]); ok && n == diskNumber {
		return true
	}
	return false
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
