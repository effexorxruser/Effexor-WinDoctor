// Package targetresolver builds deterministic advisory Windows boot topology
// from Case snapshot evidence. It does not write Case Store, create Findings,
// or perform mutation.
package targetresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/evidenceview"
)

const (
	resolverID      = "effexor-recovery-target-resolver"
	resolverVersion = "1.0.0"
	collectorName   = "effexor-recovery-target-resolver"
	espGPTTypeGUID  = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
)

// TechnicianSelection optionally pins topology roles.
type TechnicianSelection struct {
	WindowsTargetID          string
	WindowsPartitionTargetID string
	SystemDiskTargetID       string
	ESPTargetID              string
	BCDTargetID              string
}

// Request is the pure resolver input.
type Request struct {
	Snapshot  casestore.Snapshot
	CommitID  string
	Selection *TechnicianSelection
	Now       time.Time // optional; defaults to UTC now for generated_at only
}

// Result is advisory topology plus EvidenceBundle for acquisition.
type Result struct {
	Topology domain.WindowsBootTopology
	Evidence domain.EvidenceBundle
}

// Resolve builds a deterministic Windows boot topology from Case evidence.
func Resolve(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if request.CommitID == "" {
		return Result{}, fmt.Errorf("commit_id is required")
	}
	if err := request.Snapshot.Validate(); err != nil {
		return Result{}, fmt.Errorf("snapshot: %w", err)
	}
	idx, err := buildIndex(request.Snapshot)
	if err != nil {
		return Result{}, err
	}
	if idx.firmwareTarget == nil {
		return Result{}, fmt.Errorf("firmware target is required for topology evidence")
	}

	firmwareMode, fwAmb, fwLim := resolveFirmware(idx)
	candidates := make([]domain.TopologyCandidate, 0)
	relations := make([]domain.TopologyRelation, 0)
	ambiguities := append([]domain.TopologyAmbiguity(nil), fwAmb...)
	limitations := append([]string(nil), fwLim...)
	blockers := make([]string, 0)

	candidates = append(candidates, domain.TopologyCandidate{
		CandidateID:    "cand.firmware." + shortHash(idx.firmwareTarget.TargetID),
		Role:           domain.RoleFirmware,
		TargetID:       idx.firmwareTarget.TargetID,
		Confidence:     firmwareConfidence(firmwareMode),
		EvidenceRefs:   uniqueSorted(idx.evidenceIDsForTarget(idx.firmwareTarget.TargetID)),
		RationaleCodes: []string{"firmware_mode_observed"},
		Limitations:    []string{},
	})

	windowsCands, windowsRels, windowsAmb, windowsLim := resolveWindows(idx)
	candidates = append(candidates, windowsCands...)
	relations = append(relations, windowsRels...)
	ambiguities = append(ambiguities, windowsAmb...)
	limitations = append(limitations, windowsLim...)

	espCands, espRels, espAmb, espLim := resolveESP(idx)
	candidates = append(candidates, espCands...)
	relations = append(relations, espRels...)
	ambiguities = append(ambiguities, espAmb...)
	limitations = append(limitations, espLim...)

	bcdCands, bcdRels, bcdAmb, bcdLim := resolveBCD(idx)
	candidates = append(candidates, bcdCands...)
	relations = append(relations, bcdRels...)
	ambiguities = append(ambiguities, bcdAmb...)
	limitations = append(limitations, bcdLim...)

	bitAmb, bitLim, bitBlock := resolveBitLocker(idx)
	ambiguities = append(ambiguities, bitAmb...)
	limitations = append(limitations, bitLim...)
	blockers = append(blockers, bitBlock...)

	healthAmb, healthLim, healthBlock := resolveHealth(idx)
	ambiguities = append(ambiguities, healthAmb...)
	limitations = append(limitations, healthLim...)
	blockers = append(blockers, healthBlock...)

	selection, selBlock, selAmb, err := applySelection(idx, firmwareMode, windowsCands, espCands, bcdCands, relations, request.Selection)
	if err != nil {
		return Result{}, err
	}
	blockers = append(blockers, selBlock...)
	ambiguities = append(ambiguities, selAmb...)

	blockers = append(blockers, firmwareBlockers(firmwareMode)...)
	if len(windowsCands) == 0 {
		blockers = append(blockers, "windows_missing")
	}
	if len(windowsCands) > 1 && request.Selection == nil {
		blockers = append(blockers, "windows_ambiguous")
	}
	if len(espCands) == 0 {
		blockers = append(blockers, "esp_missing")
	}
	if len(espCands) > 1 && (request.Selection == nil || request.Selection.ESPTargetID == "") {
		blockers = append(blockers, "esp_ambiguous")
	}
	if hasRuntimeOnlySelected(relations, selection) {
		blockers = append(blockers, "relation_runtime_only")
	}

	blockers = uniqueSorted(blockers)
	if blockers == nil {
		blockers = []string{}
	}
	eligible := len(blockers) == 0 && selection.Source != domain.SelectionNone
	if !eligible && selection.Source == domain.SelectionAutomatic {
		selection = domain.TopologySelection{Source: domain.SelectionNone}
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].CandidateID < candidates[j].CandidateID })
	sort.Slice(relations, func(i, j int) bool { return relations[i].RelationID < relations[j].RelationID })
	sort.Slice(ambiguities, func(i, j int) bool {
		return ambiguities[i].Code+strings.Join(ambiguities[i].TargetIDs, ",") < ambiguities[j].Code+strings.Join(ambiguities[j].TargetIDs, ",")
	})
	limitations = uniqueSorted(limitations)
	if candidates == nil {
		candidates = []domain.TopologyCandidate{}
	}
	if relations == nil {
		relations = []domain.TopologyRelation{}
	}
	if ambiguities == nil {
		ambiguities = []domain.TopologyAmbiguity{}
	}
	if limitations == nil {
		limitations = []string{}
	}

	generatedAt := request.Now.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	topo := domain.WindowsBootTopology{
		SchemaName:      domain.SchemaWindowsBootTopology,
		SchemaVersion:   domain.SchemaVersion,
		CaseID:          request.Snapshot.Case.CaseID,
		ResolverID:      resolverID,
		ResolverVersion: resolverVersion,
		SourceCommitID:  request.CommitID,
		GeneratedAt:     generatedAt.Format(time.RFC3339),
		FirmwareMode:    firmwareMode,
		Candidates:      candidates,
		Relations:       relations,
		Selection:       selection,
		Ambiguities:     ambiguities,
		Limitations:     limitations,
		MutationEligibility: domain.MutationEligibility{
			Eligible: eligible,
			Basis:    domain.MutationEligibilityDiagnosticEvidenceOnly,
			Blockers: blockers,
		},
	}
	topo.TopologyID = topologyIDFor(topo)
	if err := topo.Validate(); err != nil {
		return Result{}, fmt.Errorf("topology: %w", err)
	}

	facts, err := json.Marshal(topo)
	if err != nil {
		return Result{}, err
	}
	evidenceID := evidenceIDFor(request.Snapshot.Case.CaseID, request.CommitID, selection, idx.allEvidenceIDs(), facts)
	evidenceLim := append([]string(nil), limitations...)
	if evidenceLim == nil {
		evidenceLim = []string{}
	}
	ev := domain.EvidenceBundle{
		SchemaName:       domain.SchemaEvidenceBundle,
		SchemaVersion:    domain.SchemaVersion,
		EvidenceID:       evidenceID,
		CaseID:           request.Snapshot.Case.CaseID,
		TargetID:         idx.firmwareTarget.TargetID,
		Collector:        collectorName,
		CollectorVersion: resolverVersion,
		CapturedAt:       topo.GeneratedAt,
		SourceStatus:     "ok",
		FactsSchema:      domain.SchemaWindowsBootTopology,
		Facts:            facts,
		Artifacts:        []domain.ArtifactRef{},
		Limitations:      evidenceLim,
	}
	if err := ev.Validate(); err != nil {
		return Result{}, fmt.Errorf("evidence: %w", err)
	}
	return Result{Topology: topo, Evidence: ev}, nil
}

type index struct {
	targets         map[string]domain.Target
	bundlesByTarget map[string][]domain.EvidenceBundle
	views           map[string]evidenceview.View
	firmwareTarget  *domain.Target
	byType          map[string][]domain.Target
}

func buildIndex(snap casestore.Snapshot) (*index, error) {
	idx := &index{
		targets:         make(map[string]domain.Target, len(snap.Targets)),
		bundlesByTarget: make(map[string][]domain.EvidenceBundle),
		views:           make(map[string]evidenceview.View),
		byType:          make(map[string][]domain.Target),
	}
	for _, t := range snap.Targets {
		idx.targets[t.TargetID] = t
		idx.byType[t.TargetType] = append(idx.byType[t.TargetType], t)
		if t.TargetType == "firmware" && idx.firmwareTarget == nil {
			tt := t
			idx.firmwareTarget = &tt
		}
	}
	for _, b := range snap.EvidenceBundles {
		idx.bundlesByTarget[b.TargetID] = append(idx.bundlesByTarget[b.TargetID], b)
		view, err := evidenceview.DecodeBundle(b)
		if err != nil {
			if errorsIsUnsupported(err) {
				continue
			}
			return nil, err
		}
		idx.views[b.EvidenceID] = view
	}
	for typ := range idx.byType {
		sort.Slice(idx.byType[typ], func(i, j int) bool {
			return idx.byType[typ][i].TargetID < idx.byType[typ][j].TargetID
		})
	}
	return idx, nil
}

func errorsIsUnsupported(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unsupported facts schema")
}

func (idx *index) evidenceIDsForTarget(targetID string) []string {
	out := make([]string, 0, len(idx.bundlesByTarget[targetID]))
	for _, b := range idx.bundlesByTarget[targetID] {
		out = append(out, b.EvidenceID)
	}
	return out
}

func (idx *index) allEvidenceIDs() []string {
	out := make([]string, 0)
	for id := range idx.views {
		out = append(out, id)
	}
	return uniqueSorted(out)
}

func resolveFirmware(idx *index) (domain.FirmwareMode, []domain.TopologyAmbiguity, []string) {
	modes := make([]string, 0)
	for _, t := range idx.byType["firmware"] {
		for _, b := range idx.bundlesByTarget[t.TargetID] {
			view, ok := idx.views[b.EvidenceID]
			if !ok {
				continue
			}
			fw, err := view.Firmware()
			if err != nil {
				continue
			}
			if fw.BootFirmwareMode != "" {
				modes = append(modes, strings.ToLower(fw.BootFirmwareMode))
			}
			if fw.HardwareFirmwareMode != "" {
				modes = append(modes, strings.ToLower(fw.HardwareFirmwareMode))
			}
		}
	}
	modes = uniqueSorted(modes)
	switch len(modes) {
	case 0:
		return domain.FirmwareUnknown, nil, []string{"firmware_mode_absent"}
	case 1:
		switch modes[0] {
		case "uefi":
			return domain.FirmwareUEFI, nil, nil
		case "bios", "legacy":
			return domain.FirmwareBIOS, nil, nil
		default:
			return domain.FirmwareUnknown, nil, []string{"firmware_mode_unrecognized"}
		}
	default:
		return domain.FirmwareConflicting, []domain.TopologyAmbiguity{{
			Code: "firmware_conflicting", Message: "conflicting firmware mode evidence",
			TargetIDs: targetIDs(idx.byType["firmware"]), EvidenceRefs: idx.allEvidenceIDs(),
		}}, []string{"firmware_mode_conflicting"}
	}
}

func firmwareConfidence(mode domain.FirmwareMode) domain.TopologyConfidence {
	switch mode {
	case domain.FirmwareUEFI, domain.FirmwareBIOS:
		return domain.ConfidenceProven
	case domain.FirmwareConflicting:
		return domain.ConfidenceAmbiguous
	default:
		return domain.ConfidenceUnknown
	}
}

func firmwareBlockers(mode domain.FirmwareMode) []string {
	switch mode {
	case domain.FirmwareUnknown:
		return []string{"firmware_unknown"}
	case domain.FirmwareConflicting:
		return []string{"firmware_conflicting"}
	case domain.FirmwareBIOS:
		return []string{"firmware_not_uefi", "unsupported_layout"}
	default:
		return nil
	}
}

func resolveWindows(idx *index) ([]domain.TopologyCandidate, []domain.TopologyRelation, []domain.TopologyAmbiguity, []string) {
	cands := make([]domain.TopologyCandidate, 0)
	rels := make([]domain.TopologyRelation, 0)
	amb := make([]domain.TopologyAmbiguity, 0)
	lims := make([]string, 0)
	for _, t := range idx.byType["windows_installation"] {
		refs := idx.evidenceIDsForTarget(t.TargetID)
		cands = append(cands, domain.TopologyCandidate{
			CandidateID:    "cand.windows." + shortHash(t.TargetID),
			Role:           domain.RoleWindowsInstallation,
			TargetID:       t.TargetID,
			Confidence:     domain.ConfidenceStrongInference,
			EvidenceRefs:   uniqueSorted(refs),
			RationaleCodes: []string{"windows_installation_present"},
			Limitations:    []string{},
		})
		partIDs := relatedPartitions(idx, t.TargetID)
		letter := driveLetterFromLocators(t.RuntimeLocators)
		if letter != "" {
			lims = append(lims, "drive_letter_runtime_only")
		}
		switch len(partIDs) {
		case 1:
			conf := domain.ConfidenceStrongInference
			code := "hosts_windows_related"
			if letterOnlyRelation(idx, t.TargetID, partIDs[0]) {
				conf = domain.ConfidenceRuntimeOnly
				code = "hosts_windows_drive_letter"
			}
			rels = append(rels, domain.TopologyRelation{
				RelationID:   "rel.hosts_windows." + shortHash(t.TargetID+partIDs[0]),
				RelationType: domain.RelationHostsWindows,
				FromTargetID: partIDs[0], ToTargetID: t.TargetID,
				Confidence: conf, EvidenceRefs: uniqueSorted(refs),
				RationaleCodes: []string{code}, Limitations: []string{},
			})
			cands = append(cands, domain.TopologyCandidate{
				CandidateID: "cand.windows_partition." + shortHash(partIDs[0]),
				Role:        domain.RoleWindowsPartition, TargetID: partIDs[0],
				Confidence: conf, EvidenceRefs: uniqueSorted(idx.evidenceIDsForTarget(partIDs[0])),
				RationaleCodes: []string{"windows_partition_linked"}, Limitations: []string{},
			})
			diskIDs := relatedDisks(idx, partIDs[0])
			if len(diskIDs) == 1 {
				rels = append(rels, domain.TopologyRelation{
					RelationID:   "rel.contains." + shortHash(diskIDs[0]+partIDs[0]),
					RelationType: domain.RelationContains,
					FromTargetID: diskIDs[0], ToTargetID: partIDs[0],
					Confidence:     domain.ConfidenceStrongInference,
					EvidenceRefs:   uniqueSorted(idx.evidenceIDsForTarget(partIDs[0])),
					RationaleCodes: []string{"partition_disk_related"}, Limitations: []string{},
				})
				cands = append(cands, domain.TopologyCandidate{
					CandidateID: "cand.system_disk." + shortHash(diskIDs[0]),
					Role:        domain.RoleSystemDisk, TargetID: diskIDs[0],
					Confidence:     domain.ConfidenceStrongInference,
					EvidenceRefs:   uniqueSorted(idx.evidenceIDsForTarget(diskIDs[0])),
					RationaleCodes: []string{"system_disk_linked"}, Limitations: []string{},
				})
			} else if len(diskIDs) > 1 {
				amb = append(amb, domain.TopologyAmbiguity{
					Code: "system_disk_unresolved", Message: "multiple disks related to windows partition",
					TargetIDs: diskIDs, EvidenceRefs: refs,
				})
			}
		case 0:
			if letter != "" {
				amb = append(amb, domain.TopologyAmbiguity{
					Code: "windows_partition_unresolved", Message: "windows root drive letter has no matching partition",
					TargetIDs: []string{t.TargetID}, EvidenceRefs: refs,
				})
			}
		default:
			amb = append(amb, domain.TopologyAmbiguity{
				Code: "windows_partition_unresolved", Message: "multiple partitions related to windows installation",
				TargetIDs: append([]string{t.TargetID}, partIDs...), EvidenceRefs: refs,
			})
		}
	}
	return cands, rels, amb, uniqueSorted(lims)
}

func resolveESP(idx *index) ([]domain.TopologyCandidate, []domain.TopologyRelation, []domain.TopologyAmbiguity, []string) {
	cands := make([]domain.TopologyCandidate, 0)
	rels := make([]domain.TopologyRelation, 0)
	amb := make([]domain.TopologyAmbiguity, 0)
	lims := make([]string, 0)
	for _, t := range idx.byType["partition"] {
		refs := idx.evidenceIDsForTarget(t.TargetID)
		gpt := ""
		weak := false
		for _, b := range idx.bundlesByTarget[t.TargetID] {
			view, ok := idx.views[b.EvidenceID]
			if !ok {
				continue
			}
			part, err := view.Partition()
			if err != nil {
				continue
			}
			if normalizeGUID(part.GPTType) == espGPTTypeGUID {
				gpt = part.GPTType
			}
			if strings.Contains(strings.ToUpper(part.Type), "EFI") || strings.Contains(strings.ToUpper(part.Type), "SYSTEM") {
				weak = true
			}
		}
		conf := domain.TopologyConfidence(domain.ConfidenceUnknown)
		codes := []string{}
		if gpt != "" {
			conf = domain.ConfidenceProven
			codes = append(codes, "esp_gpt_type_guid")
		} else if weak {
			conf = domain.ConfidenceAmbiguous
			codes = append(codes, "esp_weak_type_field")
			lims = append(lims, "esp_weak_type_only")
		} else {
			continue
		}
		cands = append(cands, domain.TopologyCandidate{
			CandidateID: "cand.esp." + shortHash(t.TargetID),
			Role:        domain.RoleEFISystemPartition, TargetID: t.TargetID,
			Confidence: conf, EvidenceRefs: uniqueSorted(refs),
			RationaleCodes: codes, Limitations: []string{},
		})
		for _, diskID := range relatedDisks(idx, t.TargetID) {
			rels = append(rels, domain.TopologyRelation{
				RelationID:   "rel.hosts_esp." + shortHash(diskID+t.TargetID),
				RelationType: domain.RelationHostsESP,
				FromTargetID: diskID, ToTargetID: t.TargetID,
				Confidence: conf, EvidenceRefs: uniqueSorted(refs),
				RationaleCodes: []string{"esp_on_disk"}, Limitations: []string{},
			})
		}
	}
	if len(cands) > 1 {
		ids := make([]string, 0, len(cands))
		for _, c := range cands {
			ids = append(ids, c.TargetID)
		}
		amb = append(amb, domain.TopologyAmbiguity{
			Code: "esp_ambiguous", Message: "multiple EFI system partition candidates",
			TargetIDs: ids, EvidenceRefs: idx.allEvidenceIDs(),
		})
	}
	return cands, rels, amb, uniqueSorted(lims)
}

func resolveBCD(idx *index) ([]domain.TopologyCandidate, []domain.TopologyRelation, []domain.TopologyAmbiguity, []string) {
	cands := make([]domain.TopologyCandidate, 0)
	rels := make([]domain.TopologyRelation, 0)
	amb := make([]domain.TopologyAmbiguity, 0)
	lims := make([]string, 0)
	for _, t := range idx.byType["boot_store"] {
		refs := idx.evidenceIDsForTarget(t.TargetID)
		cands = append(cands, domain.TopologyCandidate{
			CandidateID: "cand.bcd." + shortHash(t.TargetID),
			Role:        domain.RoleBCDStore, TargetID: t.TargetID,
			Confidence: domain.ConfidenceStrongInference, EvidenceRefs: uniqueSorted(refs),
			RationaleCodes: []string{"bcd_store_present"}, Limitations: []string{},
		})
		partIDs := relatedPartitions(idx, t.TargetID)
		switch len(partIDs) {
		case 1:
			conf := domain.ConfidenceStrongInference
			if letterOnlyRelation(idx, t.TargetID, partIDs[0]) {
				conf = domain.ConfidenceRuntimeOnly
				lims = append(lims, "bcd_drive_letter_runtime_only")
			}
			rels = append(rels, domain.TopologyRelation{
				RelationID:   "rel.contains_bcd." + shortHash(partIDs[0]+t.TargetID),
				RelationType: domain.RelationContainsBCDStore,
				FromTargetID: partIDs[0], ToTargetID: t.TargetID,
				Confidence: conf, EvidenceRefs: uniqueSorted(refs),
				RationaleCodes: []string{"bcd_partition_linked"}, Limitations: []string{},
			})
		case 0:
			amb = append(amb, domain.TopologyAmbiguity{
				Code: "bcd_missing", Message: "bcd store has no related partition",
				TargetIDs: []string{t.TargetID}, EvidenceRefs: refs,
			})
		default:
			amb = append(amb, domain.TopologyAmbiguity{
				Code: "bcd_ambiguous", Message: "bcd store related to multiple partitions",
				TargetIDs: append([]string{t.TargetID}, partIDs...), EvidenceRefs: refs,
			})
		}
	}
	return cands, rels, amb, uniqueSorted(lims)
}

func resolveBitLocker(idx *index) ([]domain.TopologyAmbiguity, []string, []string) {
	amb := make([]domain.TopologyAmbiguity, 0)
	lims := make([]string, 0)
	block := make([]string, 0)
	for _, t := range idx.byType["volume"] {
		_ = t
	}
	for _, b := range idx.views {
		if b.EntityKind != "bitlocker_volume" {
			continue
		}
		bl, err := b.BitLocker()
		if err != nil {
			continue
		}
		status := strings.ToLower(bl.LockStatus + " " + bl.ProtectionStatus)
		if strings.Contains(status, "lock") || strings.Contains(status, "inaccessible") {
			block = append(block, "bitlocker_inaccessible")
			amb = append(amb, domain.TopologyAmbiguity{
				Code: "bitlocker_inaccessible", Message: "bitlocker volume is locked or inaccessible",
				TargetIDs: []string{b.Bundle.TargetID}, EvidenceRefs: []string{b.Bundle.EvidenceID},
			})
		}
	}
	for _, t := range idx.byType["firmware"] {
		for _, lim := range t.Limitations {
			if strings.Contains(lim, "bitlocker") && strings.Contains(lim, "unavailable") {
				lims = append(lims, "bitlocker_inventory_unavailable")
			}
		}
	}
	return amb, uniqueSorted(lims), uniqueSorted(block)
}

func resolveHealth(idx *index) ([]domain.TopologyAmbiguity, []string, []string) {
	amb := make([]domain.TopologyAmbiguity, 0)
	lims := make([]string, 0)
	block := make([]string, 0)
	found := false
	unsafe := false
	for _, view := range idx.views {
		if view.EntityKind != "firmware_environment" {
			continue
		}
		records, err := view.DriveHealthRecords()
		if err != nil {
			continue
		}
		if len(records) == 0 {
			continue
		}
		found = true
		for _, rec := range records {
			hs, _ := rec["health_status"].(string)
			os, _ := rec["operational_status"].(string)
			joined := strings.ToLower(hs + " " + os)
			if strings.Contains(joined, "fail") || strings.Contains(joined, "unhealthy") || strings.Contains(joined, "critical") {
				unsafe = true
			}
		}
	}
	if !found {
		block = append(block, "storage_health_unknown")
		lims = append(lims, "storage_health_unknown")
	} else if unsafe {
		block = append(block, "storage_health_unsafe")
		amb = append(amb, domain.TopologyAmbiguity{
			Code: "storage_health_unsafe", Message: "storage health reports unsafe status",
			TargetIDs: targetIDs(idx.byType["disk"]), EvidenceRefs: idx.allEvidenceIDs(),
		})
	}
	return amb, uniqueSorted(lims), uniqueSorted(block)
}

func applySelection(
	idx *index,
	firmware domain.FirmwareMode,
	windows, esp, bcd []domain.TopologyCandidate,
	relations []domain.TopologyRelation,
	sel *TechnicianSelection,
) (domain.TopologySelection, []string, []domain.TopologyAmbiguity, error) {
	if sel != nil {
		out, err := validateTechnicianSelection(idx, sel)
		if err != nil {
			return domain.TopologySelection{}, nil, nil, err
		}
		return out, nil, nil, nil
	}
	if firmware != domain.FirmwareUEFI {
		return domain.TopologySelection{Source: domain.SelectionNone}, []string{"technician_selection_required"}, nil, nil
	}
	if len(windows) != 1 || countRole(windows, domain.RoleWindowsInstallation) != 1 {
		return domain.TopologySelection{Source: domain.SelectionNone}, nil, nil, nil
	}
	win := firstRole(windows, domain.RoleWindowsInstallation)
	part := firstRole(windows, domain.RoleWindowsPartition)
	disk := firstRole(windows, domain.RoleSystemDisk)
	if part.TargetID == "" || disk.TargetID == "" {
		return domain.TopologySelection{Source: domain.SelectionNone}, []string{"windows_partition_unresolved"}, nil, nil
	}
	if !diskIsGPT(idx, disk.TargetID) {
		return domain.TopologySelection{Source: domain.SelectionNone}, []string{"disk_not_gpt"}, nil, nil
	}
	if len(filterRole(esp, domain.RoleEFISystemPartition)) != 1 {
		return domain.TopologySelection{Source: domain.SelectionNone}, nil, nil, nil
	}
	espCand := filterRole(esp, domain.RoleEFISystemPartition)[0]
	bcdID := ""
	bcdList := filterRole(bcd, domain.RoleBCDStore)
	switch len(bcdList) {
	case 0:
		// explicit absence allowed
	case 1:
		bcdID = bcdList[0].TargetID
	default:
		return domain.TopologySelection{Source: domain.SelectionNone}, []string{"bcd_ambiguous"}, nil, nil
	}
	if hasAmbiguousConfidence(relations) {
		return domain.TopologySelection{Source: domain.SelectionNone}, []string{"evidence_incomplete"}, nil, nil
	}
	return domain.TopologySelection{
		Source:                   domain.SelectionAutomatic,
		WindowsTargetID:          win.TargetID,
		WindowsPartitionTargetID: part.TargetID,
		SystemDiskTargetID:       disk.TargetID,
		ESPTargetID:              espCand.TargetID,
		BCDTargetID:              bcdID,
	}, nil, nil, nil
}

func validateTechnicianSelection(idx *index, sel *TechnicianSelection) (domain.TopologySelection, error) {
	check := func(id, wantType string) error {
		if id == "" {
			return nil
		}
		t, ok := idx.targets[id]
		if !ok {
			return fmt.Errorf("selection target %q not found", id)
		}
		if wantType != "" && t.TargetType != wantType {
			return fmt.Errorf("selection target %q has type %q want %q", id, t.TargetType, wantType)
		}
		return nil
	}
	if err := check(sel.WindowsTargetID, "windows_installation"); err != nil {
		return domain.TopologySelection{}, err
	}
	if err := check(sel.WindowsPartitionTargetID, "partition"); err != nil {
		return domain.TopologySelection{}, err
	}
	if err := check(sel.SystemDiskTargetID, "disk"); err != nil {
		return domain.TopologySelection{}, err
	}
	if err := check(sel.ESPTargetID, "partition"); err != nil {
		return domain.TopologySelection{}, err
	}
	if err := check(sel.BCDTargetID, "boot_store"); err != nil {
		return domain.TopologySelection{}, err
	}
	if sel.ESPTargetID != "" && sel.SystemDiskTargetID != "" {
		if !diskIsGPT(idx, sel.SystemDiskTargetID) {
			return domain.TopologySelection{}, fmt.Errorf("cannot select ESP on non-GPT disk")
		}
	}
	return domain.TopologySelection{
		Source:                   domain.SelectionTechnician,
		WindowsTargetID:          sel.WindowsTargetID,
		WindowsPartitionTargetID: sel.WindowsPartitionTargetID,
		SystemDiskTargetID:       sel.SystemDiskTargetID,
		ESPTargetID:              sel.ESPTargetID,
		BCDTargetID:              sel.BCDTargetID,
	}, nil
}

func relatedPartitions(idx *index, targetID string) []string {
	out := make([]string, 0)
	for _, b := range idx.bundlesByTarget[targetID] {
		view, ok := idx.views[b.EvidenceID]
		if !ok {
			continue
		}
		for _, id := range view.RelatedTargetIDs {
			if t, ok := idx.targets[id]; ok && t.TargetType == "partition" {
				out = append(out, id)
			}
		}
	}
	return uniqueSorted(out)
}

func relatedDisks(idx *index, partitionID string) []string {
	out := make([]string, 0)
	for _, b := range idx.bundlesByTarget[partitionID] {
		view, ok := idx.views[b.EvidenceID]
		if !ok {
			continue
		}
		for _, id := range view.RelatedTargetIDs {
			if t, ok := idx.targets[id]; ok && t.TargetType == "disk" {
				out = append(out, id)
			}
		}
		part, err := view.Partition()
		if err == nil && part.DiskNumber != nil {
			for _, disk := range idx.byType["disk"] {
				if n, ok := parseLocatorInt(disk.RuntimeLocators, "disk_number"); ok && n == *part.DiskNumber {
					out = append(out, disk.TargetID)
				}
			}
		}
	}
	return uniqueSorted(out)
}

func letterOnlyRelation(idx *index, fromID, toID string) bool {
	from := idx.targets[fromID]
	to := idx.targets[toID]
	fl := driveLetterFromLocators(from.RuntimeLocators)
	tl := driveLetterFromLocators(to.RuntimeLocators)
	return fl != "" && strings.EqualFold(fl, tl)
}

func driveLetterFromLocators(loc map[string]string) string {
	if loc == nil {
		return ""
	}
	return loc["drive_letter"]
}

func diskIsGPT(idx *index, diskID string) bool {
	for _, b := range idx.bundlesByTarget[diskID] {
		view, ok := idx.views[b.EvidenceID]
		if !ok {
			continue
		}
		disk, err := view.Disk()
		if err != nil {
			continue
		}
		if strings.EqualFold(disk.PartitionStyle, "GPT") {
			return true
		}
	}
	if t, ok := idx.targets[diskID]; ok {
		if style, ok := t.RuntimeLocators["partition_style"]; ok && strings.EqualFold(style, "GPT") {
			return true
		}
	}
	return false
}

func hasRuntimeOnlySelected(relations []domain.TopologyRelation, sel domain.TopologySelection) bool {
	if sel.Source == domain.SelectionNone {
		return false
	}
	selected := map[string]struct{}{
		sel.WindowsTargetID: {}, sel.WindowsPartitionTargetID: {},
		sel.SystemDiskTargetID: {}, sel.ESPTargetID: {}, sel.BCDTargetID: {},
	}
	for _, r := range relations {
		if r.Confidence != domain.ConfidenceRuntimeOnly {
			continue
		}
		if _, ok := selected[r.FromTargetID]; ok {
			return true
		}
		if _, ok := selected[r.ToTargetID]; ok {
			return true
		}
	}
	return false
}

func hasAmbiguousConfidence(relations []domain.TopologyRelation) bool {
	for _, r := range relations {
		if r.Confidence == domain.ConfidenceAmbiguous {
			return true
		}
	}
	return false
}

func filterRole(cands []domain.TopologyCandidate, role domain.TopologyRole) []domain.TopologyCandidate {
	out := make([]domain.TopologyCandidate, 0)
	for _, c := range cands {
		if c.Role == role {
			out = append(out, c)
		}
	}
	return out
}

func countRole(cands []domain.TopologyCandidate, role domain.TopologyRole) int {
	return len(filterRole(cands, role))
}

func firstRole(cands []domain.TopologyCandidate, role domain.TopologyRole) domain.TopologyCandidate {
	list := filterRole(cands, role)
	if len(list) == 0 {
		return domain.TopologyCandidate{}
	}
	return list[0]
}

func targetIDs(targets []domain.Target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.TargetID)
	}
	return uniqueSorted(out)
}

func parseLocatorInt(loc map[string]string, key string) (int64, bool) {
	if loc == nil {
		return 0, false
	}
	s, ok := loc[key]
	if !ok {
		return 0, false
	}
	var n int64
	_, err := fmt.Sscan(s, &n)
	return n, err == nil
}

func normalizeGUID(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "{")
	v = strings.TrimSuffix(v, "}")
	return strings.ToLower(v)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func shortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:12]
}

func topologyIDFor(topo domain.WindowsBootTopology) string {
	clone := topo
	clone.TopologyID = ""
	clone.GeneratedAt = ""
	raw, _ := json.Marshal(clone)
	sum := sha256.Sum256(raw)
	return "topology-" + hex.EncodeToString(sum[:12])
}

func evidenceIDFor(caseID, commitID string, sel domain.TopologySelection, inputEvidence []string, facts []byte) string {
	type key struct {
		CaseID, CommitID string
		Selection        domain.TopologySelection
		InputEvidence    []string
		FactsSHA         string
	}
	sumFacts := sha256.Sum256(facts)
	payload, _ := json.Marshal(key{
		CaseID: caseID, CommitID: commitID, Selection: sel,
		InputEvidence: uniqueSorted(inputEvidence),
		FactsSHA:      hex.EncodeToString(sumFacts[:]),
	})
	sum := sha256.Sum256(payload)
	return "evidence-" + hex.EncodeToString(sum[:12])
}
