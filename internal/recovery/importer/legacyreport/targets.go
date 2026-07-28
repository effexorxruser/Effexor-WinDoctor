package legacyreport

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/diagnostics"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

type orderedEntity struct {
	sourcePath  string
	targetType  string
	displayName string
	entityKind  string
	payload     any
	locators    map[string]string
	limitations []string
	sourceIndex int
	sortKey     string
}

func buildTargetsAndEvidence(ctx *importContext) ([]domain.Target, []domain.EvidenceBundle, error) {
	entities, err := collectOrderedEntities(ctx)
	if err != nil {
		return nil, nil, err
	}

	targets := make([]domain.Target, 0, len(entities))
	bundles := make([]domain.EvidenceBundle, 0, len(entities))

	// First pass: create targets so relation maps can resolve.
	for _, ent := range entities {
		fp, err := entityFingerprint(ent.payload)
		if err != nil {
			return nil, nil, err
		}
		targetID := targetIDFrom(ctx.caseID, ent.sourcePath)
		limitations := append([]string{}, ent.limitations...)
		limitations = appendUnique(limitations, limReportScoped)
		if ent.targetType == "partition" || ent.targetType == "volume" || ent.targetType == "windows_installation" {
			limitations = appendUnique(limitations, limDriveLetters)
		}

		target := domain.Target{
			SchemaName:      domain.SchemaTarget,
			SchemaVersion:   domain.SchemaVersion,
			TargetID:        targetID,
			TargetType:      ent.targetType,
			DiscoveredAt:    ctx.capturedAt,
			DisplayName:     ent.displayName,
			StableIdentity:  reportScopedIdentity(ctx.normalizedSHA256, ent.sourcePath, fp),
			RuntimeLocators: ent.locators,
			Capabilities:    []string{"legacy_evidence_available"},
			Limitations:     limitations,
		}
		targets = append(targets, target)

		switch ent.entityKind {
		case "disk":
			if n, ok := parseLocatorInt(ent.locators, "disk_number"); ok {
				ctx.diskByNumber[n] = append(ctx.diskByNumber[n], targetID)
			}
		case "partition":
			if n, ok := parseLocatorInt(ent.locators, "disk_number"); ok {
				ctx.partitionByDisk[n] = append(ctx.partitionByDisk[n], targetID)
			}
			if letter, ok := ent.locators["drive_letter"]; ok {
				key := strings.ToUpper(letter)
				ctx.partitionByLetter[key] = append(ctx.partitionByLetter[key], targetID)
			}
		}
	}

	// Second pass: evidence with related_target_ids.
	for i, ent := range entities {
		targetID := targets[i].TargetID
		related, lims, warns := relatedTargetIDs(ctx, ent)
		ctx.warnings = append(ctx.warnings, warns...)

		factsLimitations := append([]string{}, ent.limitations...)
		factsLimitations = append(factsLimitations, lims...)
		if ent.entityKind == "firmware_environment" {
			factsLimitations = appendUnique(factsLimitations, limDriveHealth)
			if ctx.report.Storage.BitLockerInventory.Status == diagnostics.BitLockerStatusUnavailable {
				factsLimitations = appendUnique(factsLimitations, limBitLockerNA)
			}
		}

		facts, err := buildFacts(ctx, ent, related, factsLimitations)
		if err != nil {
			return nil, nil, err
		}
		factsRaw, err := jsonMarshal(facts)
		if err != nil {
			return nil, nil, err
		}

		bundleLimitations := append([]string{}, targets[i].Limitations...)
		for _, lim := range lims {
			bundleLimitations = appendUnique(bundleLimitations, lim)
		}
		if ent.entityKind == "firmware_environment" {
			bundleLimitations = appendUnique(bundleLimitations, limDriveHealth)
			if ctx.report.Storage.BitLockerInventory.Status == diagnostics.BitLockerStatusUnavailable {
				bundleLimitations = appendUnique(bundleLimitations, limBitLockerNA)
			}
		}

		bundles = append(bundles, domain.EvidenceBundle{
			SchemaName:       domain.SchemaEvidenceBundle,
			SchemaVersion:    domain.SchemaVersion,
			EvidenceID:       evidenceIDFrom(ctx.caseID, targetID, factsSchemaVersion),
			CaseID:           ctx.caseID,
			TargetID:         targetID,
			Collector:        importerName,
			CollectorVersion: importerVersion,
			CapturedAt:       ctx.capturedAt,
			SourceStatus:     sourceStatusFor(ent.entityKind, ctx.report.Storage.BitLockerInventory.Status),
			FactsSchema:      FactsSchemaID,
			Facts:            factsRaw,
			Artifacts:        append([]domain.ArtifactRef{}, ctx.artifacts...),
			Limitations:      bundleLimitations,
		})
	}

	return targets, bundles, nil
}

func collectOrderedEntities(ctx *importContext) ([]orderedEntity, error) {
	report := ctx.report
	out := make([]orderedEntity, 0, 1+len(report.Storage.Disks)+len(report.Storage.Partitions)+len(report.Installations)+len(report.Boot.BCDStores)+len(report.Storage.BitLockerVolumes))

	firmwarePayload := map[string]any{
		"environment":         report.Environment,
		"hardware":            report.Hardware,
		"boot_firmware_mode":  report.Boot.FirmwareMode,
		"checks":              report.Checks,
		"privacy":             report.Privacy,
		"drive_health":        report.Storage.DriveHealth,
		"bitlocker_inventory": report.Storage.BitLockerInventory,
	}
	out = append(out, orderedEntity{
		sourcePath:  "firmware",
		targetType:  "firmware",
		displayName: "Firmware and host environment",
		entityKind:  "firmware_environment",
		payload:     firmwarePayload,
		locators:    map[string]string{},
		limitations: []string{},
		sourceIndex: 0,
		sortKey:     "0-firmware",
	})

	type indexedDisk struct {
		index int
		disk  diagnostics.Disk
	}
	disks := make([]indexedDisk, len(report.Storage.Disks))
	for i, d := range report.Storage.Disks {
		disks[i] = indexedDisk{index: i, disk: d}
	}
	sort.SliceStable(disks, func(i, j int) bool {
		if disks[i].disk.Number != disks[j].disk.Number {
			return disks[i].disk.Number < disks[j].disk.Number
		}
		return disks[i].index < disks[j].index
	})
	for _, item := range disks {
		path := fmt.Sprintf("storage.disks[%d]", item.index)
		name := item.disk.FriendlyName
		if strings.TrimSpace(name) == "" {
			name = fmt.Sprintf("Disk %d", item.disk.Number)
		}
		locators := map[string]string{}
		lims := []string{}
		putLocator(locators, &lims, path, "disk_number", strconv.Itoa(item.disk.Number))
		out = append(out, orderedEntity{
			sourcePath:  path,
			targetType:  "disk",
			displayName: name,
			entityKind:  "disk",
			payload:     item.disk,
			locators:    locators,
			limitations: lims,
			sourceIndex: item.index,
			sortKey:     fmt.Sprintf("1-disk-%010d-%010d", item.disk.Number, item.index),
		})
	}

	type indexedPart struct {
		index int
		part  diagnostics.Partition
	}
	parts := make([]indexedPart, len(report.Storage.Partitions))
	for i, p := range report.Storage.Partitions {
		parts[i] = indexedPart{index: i, part: p}
	}
	sort.SliceStable(parts, func(i, j int) bool {
		if parts[i].part.DiskNumber != parts[j].part.DiskNumber {
			return parts[i].part.DiskNumber < parts[j].part.DiskNumber
		}
		if parts[i].part.PartitionNumber != parts[j].part.PartitionNumber {
			return parts[i].part.PartitionNumber < parts[j].part.PartitionNumber
		}
		return parts[i].index < parts[j].index
	})
	for _, item := range parts {
		path := fmt.Sprintf("storage.partitions[%d]", item.index)
		locators := map[string]string{}
		lims := []string{}
		putLocator(locators, &lims, path, "disk_number", strconv.Itoa(item.part.DiskNumber))
		putLocator(locators, &lims, path, "partition_number", strconv.Itoa(item.part.PartitionNumber))
		putDriveLetterLocator(locators, &lims, path, "drive_letter", item.part.DriveLetter)
		out = append(out, orderedEntity{
			sourcePath:  path,
			targetType:  "partition",
			displayName: fmt.Sprintf("Disk %d Partition %d", item.part.DiskNumber, item.part.PartitionNumber),
			entityKind:  "partition",
			payload:     item.part,
			locators:    locators,
			limitations: lims,
			sourceIndex: item.index,
			sortKey:     fmt.Sprintf("2-part-%010d-%010d-%010d", item.part.DiskNumber, item.part.PartitionNumber, item.index),
		})
	}

	type indexedInstall struct {
		index int
		inst  diagnostics.Installation
	}
	installs := make([]indexedInstall, len(report.Installations))
	for i, inst := range report.Installations {
		installs[i] = indexedInstall{index: i, inst: inst}
	}
	sort.SliceStable(installs, func(i, j int) bool {
		ni := normalizePathKey(installs[i].inst.Root)
		nj := normalizePathKey(installs[j].inst.Root)
		if ni != nj {
			return ni < nj
		}
		return installs[i].index < installs[j].index
	})
	for _, item := range installs {
		path := fmt.Sprintf("windows_installations[%d]", item.index)
		locators := map[string]string{}
		lims := []string{}
		putLocator(locators, &lims, path, "root", item.inst.Root)
		putLocator(locators, &lims, path, "system_hive", item.inst.SystemHive)
		putLocator(locators, &lims, path, "software_hive", item.inst.SoftwareHive)
		displayRoot := item.inst.Root
		if displayRoot == "" {
			displayRoot = path
		}
		out = append(out, orderedEntity{
			sourcePath:  path,
			targetType:  "windows_installation",
			displayName: fmt.Sprintf("Windows installation %s", displayRoot),
			entityKind:  "windows_installation",
			payload:     item.inst,
			locators:    locators,
			limitations: lims,
			sourceIndex: item.index,
			sortKey:     fmt.Sprintf("3-win-%s-%010d", normalizePathKey(item.inst.Root), item.index),
		})
	}

	type indexedBCD struct {
		index int
		store diagnostics.BCDStore
	}
	stores := make([]indexedBCD, len(report.Boot.BCDStores))
	for i, s := range report.Boot.BCDStores {
		stores[i] = indexedBCD{index: i, store: s}
	}
	sort.SliceStable(stores, func(i, j int) bool {
		if stores[i].store.Kind != stores[j].store.Kind {
			return stores[i].store.Kind < stores[j].store.Kind
		}
		if stores[i].store.Path != stores[j].store.Path {
			return stores[i].store.Path < stores[j].store.Path
		}
		return stores[i].index < stores[j].index
	})
	for _, item := range stores {
		path := fmt.Sprintf("boot.bcd_stores[%d]", item.index)
		locators := map[string]string{}
		lims := []string{}
		putLocator(locators, &lims, path, "path", item.store.Path)
		putLocator(locators, &lims, path, "kind", item.store.Kind)
		out = append(out, orderedEntity{
			sourcePath:  path,
			targetType:  "boot_store",
			displayName: fmt.Sprintf("BCD store (%s)", item.store.Kind),
			entityKind:  "boot_store",
			payload:     item.store,
			locators:    locators,
			limitations: lims,
			sourceIndex: item.index,
			sortKey:     fmt.Sprintf("4-bcd-%s-%s-%010d", item.store.Kind, normalizePathKey(item.store.Path), item.index),
		})
	}

	status := report.Storage.BitLockerInventory.Status
	if status == diagnostics.BitLockerStatusOK || status == diagnostics.BitLockerStatusPartial {
		type indexedVol struct {
			index int
			vol   diagnostics.BitLockerVolume
		}
		vols := make([]indexedVol, len(report.Storage.BitLockerVolumes))
		for i, v := range report.Storage.BitLockerVolumes {
			vols[i] = indexedVol{index: i, vol: v}
		}
		sort.SliceStable(vols, func(i, j int) bool {
			if vols[i].vol.MountPoint != vols[j].vol.MountPoint {
				return vols[i].vol.MountPoint < vols[j].vol.MountPoint
			}
			return vols[i].index < vols[j].index
		})
		for _, item := range vols {
			path := fmt.Sprintf("storage.bitlocker_volumes[%d]", item.index)
			locators := map[string]string{}
			lims := []string{}
			putLocator(locators, &lims, path, "mount_point", item.vol.MountPoint)
			out = append(out, orderedEntity{
				sourcePath:  path,
				targetType:  "volume",
				displayName: fmt.Sprintf("BitLocker volume %s", item.vol.MountPoint),
				entityKind:  "bitlocker_volume",
				payload:     item.vol,
				locators:    locators,
				limitations: lims,
				sourceIndex: item.index,
				sortKey:     fmt.Sprintf("5-bl-%s-%010d", normalizePathKey(item.vol.MountPoint), item.index),
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].sortKey < out[j].sortKey
	})
	return out, nil
}

func sourceStatusFor(entityKind, bitLockerInventoryStatus string) string {
	if entityKind == "bitlocker_volume" {
		switch bitLockerInventoryStatus {
		case diagnostics.BitLockerStatusPartial:
			return "partial"
		default:
			return "ok"
		}
	}
	return "ok"
}

// putLocator adds a runtime locator only when the value is usable.
// Empty, NUL, and whitespace-only values are omitted with a limitation.
func putLocator(dst map[string]string, lims *[]string, sourcePath, key, value string) {
	if isUsableLocator(value) {
		dst[key] = value
		return
	}
	*lims = appendUnique(*lims, fmt.Sprintf("%s runtime locator %q omitted: empty, NUL, or whitespace", sourcePath, key))
}

func putDriveLetterLocator(dst map[string]string, lims *[]string, sourcePath, key, value string) {
	if letter, ok := normalizeDriveLetterLocator(value); ok {
		dst[key] = letter
		return
	}
	*lims = appendUnique(*lims, fmt.Sprintf("%s runtime locator %q omitted: empty, NUL, whitespace, or invalid drive letter", sourcePath, key))
}

func normalizeDriveLetterLocator(raw string) (string, bool) {
	if !isUsableLocator(raw) {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimSuffix(trimmed, ":")
	if len(trimmed) != 1 {
		return "", false
	}
	c := trimmed[0]
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		return strings.ToUpper(string(c)), true
	}
	return "", false
}

func isUsableLocator(raw string) bool {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return false
	}
	if strings.TrimSpace(raw) == "" {
		return false
	}
	return true
}

func normalizePathKey(path string) string {
	return strings.ToLower(strings.ReplaceAll(path, "/", "\\"))
}

func parseLocatorInt(locators map[string]string, key string) (int, bool) {
	raw, ok := locators[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func jsonMarshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
