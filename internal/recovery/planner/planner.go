// Package planner builds deterministic draft RepairPlans from verified Case state.
// It never executes operations and never grants approval.
package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/planned"
)

const (
	PlannerID      = "effexor-recovery-planner"
	PlannerVersion = "1.0.0"
)

// Refusal is a deterministic planning refusal.
type Refusal struct {
	Codes   []string
	Message string
}

func (r Refusal) Error() string {
	return fmt.Sprintf("planner refused: %s (%s)", r.Message, strings.Join(r.Codes, ","))
}

// Result is either a draft plan or a refusal.
type Result struct {
	Plan    *domain.RepairPlan
	Refusal *Refusal
}

// Plan builds a draft RepairPlan when conservative UEFI BCD repair gates pass.
func Plan(snap casestore.Snapshot, sourceCommitID string) (Result, error) {
	if snap.WorkflowState == nil || snap.WorkflowState.State != domain.WorkflowAnalyzed {
		return Result{Refusal: &Refusal{Codes: []string{"workflow_not_analyzed"}, Message: "planner requires analyzed workflow"}}, nil
	}
	topo, topoEv, err := loadTopology(snap)
	if err != nil {
		return Result{Refusal: &Refusal{Codes: []string{"topology_missing"}, Message: err.Error()}}, nil
	}
	_ = topoEv
	if codes := topologyGateCodes(topo); len(codes) > 0 {
		return Result{Refusal: &Refusal{Codes: codes, Message: "topology is not eligible for UEFI BCD repair planning"}}, nil
	}
	bcdFindings := bcdRepairFindings(snap.Findings)
	if len(bcdFindings) == 0 {
		return Result{Refusal: &Refusal{Codes: []string{"bcd_finding_missing"}, Message: "no Boot Doctor BCD repair finding present"}}, nil
	}
	desc, ok := planned.Descriptor(planned.OpRepairUEFIBCDStore, "1.0.0")
	if !ok {
		return Result{}, fmt.Errorf("planned operation catalog unavailable")
	}
	targetID := topo.Selection.BCDTargetID
	if targetID == "" {
		targetID = topo.Selection.ESPTargetID
	}
	if targetID == "" {
		return Result{Refusal: &Refusal{Codes: []string{"bcd_target_unresolved"}, Message: "no BCD/ESP target selected"}}, nil
	}

	findingIDs := make([]string, 0, len(bcdFindings))
	for _, f := range bcdFindings {
		findingIDs = append(findingIDs, f.FindingID)
	}
	sort.Strings(findingIDs)

	step := domain.PlanStep{
		StepID:           "step-repair-uefi-bcd-1",
		OperationID:      desc.OperationID,
		OperationVersion: desc.Version,
		TargetID:         targetID,
		DependsOn:        []string{},
		ApprovalRequired: true,
		BackupRequired:   true,
	}
	plan := domain.RepairPlan{
		SchemaName:    domain.SchemaRepairPlan,
		SchemaVersion: domain.SchemaVersion,
		CaseID:        snap.Case.CaseID,
		FindingRefs:   findingIDs,
		Steps:         []domain.PlanStep{step},
		RiskSummary:   "Typed UEFI BCD store repair is planned only; backup, approval, and a future executor are required before any mutation.",
		BackupRequirements: []string{
			"bcd_store_backup",
			"efi_boot_files_backup",
			"firmware_boot_entry_snapshot",
			"partition_layout_snapshot",
			"verify:bcd_readable",
			"verify:windows_loader_entry_exists",
			"verify:loader_points_to_selected_windows",
			"verify:efi_files_exist",
			"verify:selected_disk_esp_unchanged",
		},
		ApprovalRequirements: []string{
			"explicit_technician_approval",
			"policy_allowed",
			"no_execution_without_backup_gate",
		},
		Status: "draft",
	}
	digest := planDigest(PlannerVersion, snap.Case.CaseID, sourceCommitID, topo.TopologyID, findingIDs, plan.Steps, plan.BackupRequirements, plan.ApprovalRequirements)
	plan.PlanID = "plan-" + digest[:24]
	if err := plan.Validate(); err != nil {
		return Result{}, err
	}
	return Result{Plan: &plan}, nil
}

func loadTopology(snap casestore.Snapshot) (domain.WindowsBootTopology, domain.EvidenceBundle, error) {
	for _, e := range snap.EvidenceBundles {
		if e.FactsSchema != domain.SchemaWindowsBootTopology {
			continue
		}
		var topo domain.WindowsBootTopology
		if err := json.Unmarshal(e.Facts, &topo); err != nil {
			return domain.WindowsBootTopology{}, e, fmt.Errorf("decode topology: %w", err)
		}
		return topo, e, nil
	}
	return domain.WindowsBootTopology{}, domain.EvidenceBundle{}, fmt.Errorf("windows-boot-topology evidence missing")
}

func topologyGateCodes(topo domain.WindowsBootTopology) []string {
	codes := map[string]struct{}{}
	if topo.FirmwareMode != domain.FirmwareUEFI {
		codes["firmware_not_uefi"] = struct{}{}
	}
	for _, b := range topo.MutationEligibility.Blockers {
		codes[b] = struct{}{}
	}
	if topo.Selection.Source == domain.SelectionNone {
		codes["selection_none"] = struct{}{}
	}
	if topo.Selection.WindowsTargetID == "" {
		codes["windows_missing"] = struct{}{}
	}
	if topo.Selection.ESPTargetID == "" {
		codes["esp_missing"] = struct{}{}
	}
	if topo.Selection.SystemDiskTargetID == "" {
		codes["system_disk_unresolved"] = struct{}{}
	}
	// Legacy/MBR is out of scope.
	for _, b := range topo.MutationEligibility.Blockers {
		if b == "disk_not_gpt" || b == "unsupported_layout" {
			codes["legacy_mbr_refused"] = struct{}{}
		}
	}
	out := make([]string, 0, len(codes))
	for c := range codes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func bcdRepairFindings(findings []domain.Finding) []domain.Finding {
	want := map[string]struct{}{
		bootdoctor.CodeBCDStoreMissing:                {},
		bootdoctor.CodeBCDStoreUnreadable:             {},
		bootdoctor.CodeBCDMembershipUnknown:           {},
		bootdoctor.CodeBCDWindowsEntryMissing:         {},
		bootdoctor.CodeBCDPointsToUnknownInstallation: {},
	}
	out := []domain.Finding{}
	for _, f := range findings {
		code := bootdoctor.FindingCodeOf(f)
		if _, ok := want[code]; ok {
			out = append(out, f)
		}
	}
	return out
}

func planDigest(plannerVersion, caseID, commitID, topologyID string, findings []string, steps []domain.PlanStep, backup, approval []string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "planner|%s|case=%s|commit=%s|topo=%s|", plannerVersion, caseID, commitID, topologyID)
	_, _ = fmt.Fprintf(h, "findings=%s|", strings.Join(findings, ","))
	raw, _ := json.Marshal(steps)
	_, _ = h.Write(raw)
	_, _ = fmt.Fprintf(h, "|backup=%s|approval=%s", strings.Join(backup, ","), strings.Join(approval, ","))
	return hex.EncodeToString(h.Sum(nil))
}
