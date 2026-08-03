package bootdoctor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// Input is the pure Boot Doctor analysis input.
type Input struct {
	CaseID             string
	Topology           domain.WindowsBootTopology
	TopologyEvidenceID string
	Targets            []domain.Target
	KnownEvidenceIDs   []string
	KnownTargetIDs     []string
}

// Result is the deterministic Finding set for one analysis pass.
type Result struct {
	Findings []domain.Finding
}

type draft struct {
	targets  []string
	evidence []string
	extraLim []string
	insuff   bool
}

// Analyze produces deterministic Findings from topology evidence.
// It validates topology, never reads global state, and does not mutate inputs.
func Analyze(in Input) (Result, error) {
	if strings.TrimSpace(in.CaseID) == "" {
		return Result{}, fmt.Errorf("bootdoctor: case_id is required")
	}
	topo := in.Topology
	if topo.CaseID != "" && topo.CaseID != in.CaseID {
		return Result{}, fmt.Errorf("bootdoctor: topology.case_id mismatch")
	}
	if err := topo.Validate(); err != nil {
		return Result{}, fmt.Errorf("bootdoctor: topology: %w", err)
	}
	knownEv := toSet(in.KnownEvidenceIDs)
	knownTg := toSet(in.KnownTargetIDs)
	if in.TopologyEvidenceID != "" {
		if len(knownEv) > 0 {
			if _, ok := knownEv[in.TopologyEvidenceID]; !ok {
				return Result{}, fmt.Errorf("bootdoctor: topology evidence %q is not in known evidence set", in.TopologyEvidenceID)
			}
		}
	}

	codes := collectDrafts(topo, in.TopologyEvidenceID, in.Targets)
	codes = applySuppression(codes)

	cat := catalog()
	out := make([]domain.Finding, 0, len(codes))
	for code, d := range codes {
		spec, ok := cat[code]
		if !ok {
			return Result{}, fmt.Errorf("bootdoctor: unknown finding code %q", code)
		}
		targets := uniqueSorted(d.targets)
		evidence := uniqueSorted(d.evidence)
		if err := refsExist("target", targets, knownTg); err != nil {
			return Result{}, err
		}
		if err := refsExist("evidence", evidence, knownEv); err != nil {
			return Result{}, err
		}
		if len(evidence) == 0 && !d.insuff {
			d.insuff = true
		}
		lims := []string{codeLimitPrefix + code}
		lims = append(lims, d.extraLim...)
		lims = append(lims,
			"analyzer="+analyzerID,
			"analyzer_version="+analyzerVersion,
			"topology_id="+topo.TopologyID,
		)
		if in.TopologyEvidenceID != "" {
			lims = append(lims, "topology_evidence_id="+in.TopologyEvidenceID)
		}
		lims = uniqueSorted(lims)

		workflows := cloneStrings(spec.Workflows)
		f := domain.Finding{
			SchemaName:           domain.SchemaFinding,
			SchemaVersion:        domain.SchemaVersion,
			FindingID:            findingIDFor(in.CaseID, code, targets, evidence),
			CaseID:               in.CaseID,
			Severity:             spec.Severity,
			Confidence:           spec.Confidence,
			Title:                spec.Title,
			Rationale:            spec.Rationale,
			EvidenceRefs:         evidence,
			AffectedTargetIDs:    targets,
			RecommendedWorkflows: workflows,
			Limitations:          lims,
			InsufficientEvidence: d.insuff,
		}
		if err := f.Validate(); err != nil {
			return Result{}, fmt.Errorf("bootdoctor: finding %s: %w", code, err)
		}
		out = append(out, f)
	}

	sort.Slice(out, func(i, j int) bool {
		ci, cj := FindingCodeOf(out[i]), FindingCodeOf(out[j])
		if ci != cj {
			return ci < cj
		}
		return out[i].FindingID < out[j].FindingID
	})
	return Result{Findings: out}, nil
}

func collectDrafts(topo domain.WindowsBootTopology, topoEv string, targets []domain.Target) map[string]draft {
	out := make(map[string]draft)
	add := func(code string, targets, evidence []string, insuff bool, extra ...string) {
		if code == "" {
			return
		}
		ev := append([]string{}, evidence...)
		if topoEv != "" {
			ev = append(ev, topoEv)
		}
		d := out[code]
		d.targets = append(d.targets, targets...)
		d.evidence = append(d.evidence, ev...)
		d.extraLim = append(d.extraLim, extra...)
		d.insuff = d.insuff || insuff
		out[code] = d
	}

	blockers := toSet(topo.MutationEligibility.Blockers)
	ambCodes := ambiguityCodes(topo)
	windows := candidatesByRole(topo, domain.RoleWindowsInstallation)
	parts := candidatesByRole(topo, domain.RoleWindowsPartition)
	disks := candidatesByRole(topo, domain.RoleSystemDisk)
	esps := candidatesByRole(topo, domain.RoleEFISystemPartition)
	bcds := candidatesByRole(topo, domain.RoleBCDStore)
	byID := targetsByID(targets)

	allCandTargets := candidateTargets(topo)
	topoEvidence := topologyEvidenceRefs(topo)
	hasBlock := func(code string) bool { _, ok := blockers[code]; return ok }
	hasAmb := func(code string) bool { _, ok := ambCodes[code]; return ok }

	// Firmware
	switch topo.FirmwareMode {
	case domain.FirmwareUnknown:
		add(CodeFirmwareModeUnknown, firmwareTargets(topo), topoEvidence, false)
	case domain.FirmwareConflicting:
		add(CodeFirmwareModeConflicting, firmwareTargets(topo), topoEvidence, false)
		add(CodeBootTopologyConflicting, allCandTargets, topoEvidence, false)
	case domain.FirmwareBIOS:
		add(CodeUnsupportedLegacyBootTopology, append(firmwareTargets(topo), disks...), topoEvidence, false)
		if diskStyle(byID, preferredDisk(topo, disks)) == "GPT" {
			add(CodeLegacyWithGPTLayout, append(firmwareTargets(topo), disks...), topoEvidence, false)
		}
	case domain.FirmwareUEFI:
		if diskStyle(byID, preferredDisk(topo, disks)) == "MBR" || hasBlock("disk_not_gpt") {
			add(CodeUEFIWithMBRSystemDisk, append(firmwareTargets(topo), disks...), topoEvidence, false)
		}
	}

	// Windows
	switch {
	case len(windows) == 0 || hasBlock("windows_missing"):
		add(CodeWindowsInstallationMissing, nil, topoEvidence, len(windows) == 0)
	case len(windows) > 1 || hasBlock("windows_ambiguous"):
		add(CodeMultipleWindowsInstallations, windows, topoEvidence, false)
		add(CodeWindowsInstallationAmbiguous, windows, topoEvidence, false)
		add(CodeBootTopologyAmbiguous, windows, topoEvidence, false)
	}
	if hasBlock("windows_partition_unresolved") || (len(windows) == 1 && len(parts) == 0) {
		add(CodeWindowsPartitionRelationUnknown, append(windows, parts...), topoEvidence, true)
		add(CodeWindowsInstallationIncomplete, append(windows, parts...), topoEvidence, true)
	}
	if hasBlock("system_disk_unresolved") || (len(windows) == 1 && len(disks) == 0) {
		add(CodeWindowsSystemDiskRelationUnknown, append(windows, disks...), topoEvidence, true)
		add(CodeWindowsInstallationIncomplete, append(windows, disks...), topoEvidence, true)
	}
	if len(windows) >= 1 && !hasRelationType(topo, domain.RelationHostsWindows) {
		add(CodeWindowsPartitionRelationUnknown, append(windows, parts...), topoEvidence, true)
	}

	// ESP
	switch {
	case len(esps) == 0 || hasBlock("esp_missing"):
		add(CodeEFISystemPartitionMissing, nil, topoEvidence, len(esps) == 0)
	case len(esps) > 1 || hasBlock("esp_ambiguous"):
		add(CodeMultipleEFISystemPartitions, esps, topoEvidence, false)
		add(CodeEFISystemPartitionAmbiguous, esps, topoEvidence, false)
		add(CodeBootTopologyAmbiguous, esps, topoEvidence, false)
	}
	if hasAmb("esp_cross_disk") || hasCrossDiskESP(topo) {
		add(CodeEFISystemPartitionCrossDisk, append(esps, disks...), topoEvidence, false)
		add(CodeUnsafeToAttemptBootRepair, append(esps, disks...), topoEvidence, false)
	}
	if len(esps) >= 1 && !hasRelationType(topo, domain.RelationHostsESP) {
		add(CodeEFISystemPartitionRelationUnknown, append(esps, disks...), topoEvidence, true)
	}
	if hasAmb("esp_unreadable") {
		add(CodeEFISystemPartitionUnreadable, esps, topoEvidence, false)
	}

	// BCD
	switch {
	case hasBlock("bcd_ambiguous") || len(bcds) > 1 || hasAmb("bcd_ambiguous"):
		add(CodeBCDStoreAmbiguous, bcds, topoEvidence, false)
		add(CodeBootTopologyAmbiguous, bcds, topoEvidence, false)
	case hasBlock("bcd_missing") || hasAmb("bcd_missing") || (len(bcds) == 0 && topo.Selection.Source != domain.SelectionNone):
		// Missing BCD is medium; only assert when selection exists or ambiguity says missing.
		if len(bcds) == 0 {
			add(CodeBCDStoreMissing, nil, topoEvidence, true)
		}
	}
	if hasAmb("bcd_unreadable") {
		add(CodeBCDStoreUnreadable, bcds, topoEvidence, false)
	}
	if len(bcds) >= 1 && len(windows) == 1 && !hasBCDForWindows(topo, windows[0]) {
		add(CodeBCDMembershipUnknown, append(bcds, windows...), topoEvidence, true)
		add(CodeBCDWindowsEntryMissing, append(bcds, windows...), topoEvidence, true)
	}
	if points, unknown := bcdUnknownWindows(topo, toSet(windows)); len(unknown) > 0 {
		add(CodeBCDPointsToUnknownInstallation, append(bcds, points...), topoEvidence, false)
	}
	if hasBCDCrossDisk(topo) {
		add(CodeBCDCrossDiskMismatch, append(bcds, disks...), topoEvidence, false)
		add(CodeUnsafeToAttemptBootRepair, append(bcds, disks...), topoEvidence, false)
	}

	// BitLocker
	if hasBlock("bitlocker_inaccessible") || hasAmb("bitlocker_inaccessible") {
		tg := targetsForAmbiguity(topo, "bitlocker_inaccessible")
		add(CodeBitLockerLocked, tg, topoEvidence, false)
		add(CodeBitLockerRecoveryMaterialRequired, tg, topoEvidence, false)
		add(CodeBitLockerBlocksBootAnalysis, tg, topoEvidence, false)
	}
	if hasBlock("bitlocker_status_unknown") || hasAmb("bitlocker_status_unknown") {
		tg := targetsForAmbiguity(topo, "bitlocker_status_unknown")
		add(CodeBitLockerStatusUnknown, tg, topoEvidence, true)
		add(CodeBitLockerBlocksBootAnalysis, tg, topoEvidence, true)
	}

	// Storage
	if hasBlock("storage_health_unsafe") || hasAmb("storage_health_unsafe") {
		add(CodeStorageHealthCritical, disks, topoEvidence, false)
		add(CodeUnsafeToAttemptBootRepair, disks, topoEvidence, false)
	}
	if hasAmb("storage_health_warning") {
		add(CodeStorageHealthWarning, disks, topoEvidence, false)
	}
	if hasBlock("storage_health_unknown") {
		// Distinguish missing evidence vs unknown status via limitations on topology.
		if hasLimitation(topo, "storage_health_unknown") && !hasDriveHealthAmbiguity(topo) {
			add(CodeStorageEvidenceMissing, disks, topoEvidence, true)
		}
		add(CodeStorageHealthUnknown, disks, topoEvidence, true)
	}

	// Topology completeness / selection
	if hasBlock("technician_selection_required") || topo.Selection.Source == domain.SelectionNone {
		if !topo.MutationEligibility.Eligible {
			add(CodeTechnicianSelectionRequired, allCandTargets, topoEvidence, false)
		}
	}
	if hasBlock("evidence_incomplete") || hasBlock("relation_runtime_only") {
		add(CodeBootTopologyIncomplete, allCandTargets, topoEvidence, true)
		add(CodeInsufficientEvidenceForRepairPlan, allCandTargets, topoEvidence, true)
	}
	if hasBlock("unsupported_layout") {
		add(CodeBootTopologyConflicting, allCandTargets, topoEvidence, false)
	}
	incomplete := !topo.MutationEligibility.Eligible ||
		topo.Selection.Source == domain.SelectionNone ||
		topo.Selection.WindowsTargetID == "" ||
		topo.Selection.WindowsPartitionTargetID == "" ||
		topo.Selection.SystemDiskTargetID == "" ||
		topo.Selection.ESPTargetID == ""
	if incomplete {
		add(CodeBootTopologyIncomplete, selectedOrAll(topo, allCandTargets), topoEvidence, true)
		add(CodeInsufficientEvidenceForRepairPlan, selectedOrAll(topo, allCandTargets), topoEvidence, true)
	}

	// Healthy baseline — only when fully eligible and no conflicting drafts yet.
	if topo.MutationEligibility.Eligible &&
		topo.Selection.Source != domain.SelectionNone &&
		topo.FirmwareMode == domain.FirmwareUEFI &&
		len(blockers) == 0 &&
		!hasConflictingAmbiguity(topo) {
		add(CodeBootTopologyConsistent, selectedTargets(topo), topoEvidence, false)
	}

	return out
}

func toSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	return out
}

func refsExist(kind string, ids []string, known map[string]struct{}) error {
	if len(known) == 0 {
		return nil
	}
	for _, id := range ids {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("bootdoctor: finding references unknown %s %q", kind, id)
		}
	}
	return nil
}

func candidatesByRole(topo domain.WindowsBootTopology, role domain.TopologyRole) []string {
	out := make([]string, 0)
	for _, c := range topo.Candidates {
		if c.Role == role {
			out = append(out, c.TargetID)
		}
	}
	return uniqueSorted(out)
}

func candidateTargets(topo domain.WindowsBootTopology) []string {
	out := make([]string, 0, len(topo.Candidates))
	for _, c := range topo.Candidates {
		out = append(out, c.TargetID)
	}
	return uniqueSorted(out)
}

func firmwareTargets(topo domain.WindowsBootTopology) []string {
	return candidatesByRole(topo, domain.RoleFirmware)
}

func topologyEvidenceRefs(topo domain.WindowsBootTopology) []string {
	out := make([]string, 0)
	for _, c := range topo.Candidates {
		out = append(out, c.EvidenceRefs...)
	}
	for _, r := range topo.Relations {
		out = append(out, r.EvidenceRefs...)
	}
	for _, a := range topo.Ambiguities {
		out = append(out, a.EvidenceRefs...)
	}
	return uniqueSorted(out)
}

func ambiguityCodes(topo domain.WindowsBootTopology) map[string]struct{} {
	out := make(map[string]struct{}, len(topo.Ambiguities))
	for _, a := range topo.Ambiguities {
		out[a.Code] = struct{}{}
	}
	return out
}

func targetsForAmbiguity(topo domain.WindowsBootTopology, code string) []string {
	out := make([]string, 0)
	for _, a := range topo.Ambiguities {
		if a.Code == code {
			out = append(out, a.TargetIDs...)
		}
	}
	return uniqueSorted(out)
}

func hasLimitation(topo domain.WindowsBootTopology, code string) bool {
	for _, lim := range topo.Limitations {
		if lim == code {
			return true
		}
	}
	return false
}

func hasDriveHealthAmbiguity(topo domain.WindowsBootTopology) bool {
	for _, a := range topo.Ambiguities {
		if a.Code == "storage_health_unknown" || a.Code == "storage_health_unsafe" {
			return true
		}
	}
	return false
}

func hasRelationType(topo domain.WindowsBootTopology, typ domain.TopologyRelationType) bool {
	for _, r := range topo.Relations {
		if r.RelationType == typ &&
			r.Confidence != domain.ConfidenceAmbiguous &&
			r.Confidence != domain.ConfidenceUnknown {
			return true
		}
	}
	return false
}

func hasBCDForWindows(topo domain.WindowsBootTopology, windowsID string) bool {
	for _, r := range topo.Relations {
		if r.RelationType == domain.RelationBootStoreForWindows && r.ToTargetID == windowsID {
			if r.Confidence == domain.ConfidenceAmbiguous || r.Confidence == domain.ConfidenceUnknown {
				continue
			}
			return true
		}
	}
	return false
}

func bcdUnknownWindows(topo domain.WindowsBootTopology, windows map[string]struct{}) (points, unknown []string) {
	for _, r := range topo.Relations {
		if r.RelationType != domain.RelationBootStoreForWindows {
			continue
		}
		points = append(points, r.FromTargetID, r.ToTargetID)
		if _, ok := windows[r.ToTargetID]; !ok {
			unknown = append(unknown, r.ToTargetID)
		}
	}
	return uniqueSorted(points), uniqueSorted(unknown)
}

func hasCrossDiskESP(topo domain.WindowsBootTopology) bool {
	if topo.Selection.ESPTargetID != "" && topo.Selection.SystemDiskTargetID != "" {
		for _, r := range topo.Relations {
			if r.RelationType == domain.RelationHostsESP &&
				r.FromTargetID == topo.Selection.SystemDiskTargetID &&
				r.ToTargetID == topo.Selection.ESPTargetID {
				return false
			}
		}
		for _, r := range topo.Relations {
			if r.RelationType == domain.RelationHostsESP && r.ToTargetID == topo.Selection.ESPTargetID &&
				r.FromTargetID != topo.Selection.SystemDiskTargetID {
				return true
			}
		}
	}

	// Without selection: ESP hosted on a disk that does not contain the Windows partition.
	winDisks := make(map[string]struct{})
	for _, r := range topo.Relations {
		if r.RelationType == domain.RelationContains {
			winDisks[r.FromTargetID] = struct{}{}
		}
	}
	// Narrow to disks that contain a windows-hosting partition when possible.
	winParts := make(map[string]struct{})
	for _, r := range topo.Relations {
		if r.RelationType == domain.RelationHostsWindows {
			winParts[r.FromTargetID] = struct{}{}
		}
	}
	if len(winParts) > 0 {
		winDisks = make(map[string]struct{})
		for _, r := range topo.Relations {
			if r.RelationType == domain.RelationContains {
				if _, ok := winParts[r.ToTargetID]; ok {
					winDisks[r.FromTargetID] = struct{}{}
				}
			}
		}
	}
	if len(winDisks) == 0 {
		return false
	}
	for _, r := range topo.Relations {
		if r.RelationType != domain.RelationHostsESP {
			continue
		}
		if _, ok := winDisks[r.FromTargetID]; !ok {
			return true
		}
	}
	return false
}

func hasBCDCrossDisk(topo domain.WindowsBootTopology) bool {
	esp := topo.Selection.ESPTargetID
	part := topo.Selection.WindowsPartitionTargetID
	for _, r := range topo.Relations {
		if r.RelationType != domain.RelationContainsBCDStore {
			continue
		}
		if esp != "" && r.FromTargetID != esp && part != "" && r.FromTargetID != part {
			return true
		}
	}
	return false
}

func targetsByID(targets []domain.Target) map[string]domain.Target {
	out := make(map[string]domain.Target, len(targets))
	for _, t := range targets {
		out[t.TargetID] = t
	}
	return out
}

func preferredDisk(topo domain.WindowsBootTopology, disks []string) string {
	if topo.Selection.SystemDiskTargetID != "" {
		return topo.Selection.SystemDiskTargetID
	}
	if len(disks) == 1 {
		return disks[0]
	}
	return ""
}

func diskStyle(byID map[string]domain.Target, diskID string) string {
	if diskID == "" {
		return ""
	}
	t, ok := byID[diskID]
	if !ok {
		return ""
	}
	style := strings.ToUpper(strings.TrimSpace(t.RuntimeLocators["partition_style"]))
	switch style {
	case "GPT", "MBR":
		return style
	default:
		return ""
	}
}

func containsBlocker(topo domain.WindowsBootTopology, code string) bool {
	for _, b := range topo.MutationEligibility.Blockers {
		if b == code {
			return true
		}
	}
	return false
}

func hasConflictingAmbiguity(topo domain.WindowsBootTopology) bool {
	for _, a := range topo.Ambiguities {
		switch a.Code {
		case "unsupported_layout", "storage_health_unsafe", "bitlocker_inaccessible", "bitlocker_status_unknown":
			return true
		}
	}
	return false
}

func selectedTargets(topo domain.WindowsBootTopology) []string {
	return uniqueSorted([]string{
		topo.Selection.WindowsTargetID,
		topo.Selection.WindowsPartitionTargetID,
		topo.Selection.SystemDiskTargetID,
		topo.Selection.ESPTargetID,
		topo.Selection.BCDTargetID,
	})
}

func selectedOrAll(topo domain.WindowsBootTopology, all []string) []string {
	sel := selectedTargets(topo)
	if len(sel) == 0 {
		return all
	}
	return sel
}
