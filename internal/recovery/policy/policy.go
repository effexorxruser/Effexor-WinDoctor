// Package policy independently evaluates draft RepairPlans.
// It does not trust the planner and does not execute operations.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/planned"
	readops "github.com/effexorxruser/EffexorWinPE/internal/recovery/operations/read"
)

const PolicyVersion = "1.0.0"

// Evaluate independently gates a draft RepairPlan.
func Evaluate(snap casestore.Snapshot, plan domain.RepairPlan, sourceCommitID, requestID string, now time.Time) (domain.PolicyEvaluation, error) {
	reasons := []string{}
	decision := "allowed"

	if plan.CaseID != snap.Case.CaseID {
		reasons = append(reasons, "case_mismatch")
		decision = "denied"
	}
	if plan.Status != "draft" && plan.Status != "ready" {
		reasons = append(reasons, "plan_status_invalid")
		decision = "denied"
	}
	if err := plan.Validate(); err != nil {
		reasons = append(reasons, "plan_invalid")
		decision = "denied"
	}
	if sourceCommitID == "" {
		reasons = append(reasons, "source_commit_missing")
		decision = "denied"
	}
	if snap.WorkflowState == nil ||
		(snap.WorkflowState.State != domain.WorkflowAnalyzed && snap.WorkflowState.State != domain.WorkflowPlanProposed) {
		reasons = append(reasons, "workflow_not_ready")
		decision = "denied"
	}

	if len(plan.FindingRefs) == 0 {
		reasons = append(reasons, "finding_refs_empty")
		decision = "denied"
	}
	if planStepCycle(plan.Steps) {
		reasons = append(reasons, "plan_step_cycle")
		decision = "denied"
	}
	findingIDs := map[string]struct{}{}
	for _, f := range snap.Findings {
		findingIDs[f.FindingID] = struct{}{}
	}
	targetIDs := map[string]struct{}{}
	for _, t := range snap.Targets {
		targetIDs[t.TargetID] = struct{}{}
	}
	for _, id := range plan.FindingRefs {
		if _, ok := findingIDs[id]; !ok {
			reasons = append(reasons, "finding_ref_missing")
			decision = "denied"
		}
	}
	for _, step := range plan.Steps {
		if _, ok := targetIDs[step.TargetID]; !ok {
			reasons = append(reasons, "target_ref_missing")
			decision = "denied"
		}
		if containsCommandField(step.StepID) || containsCommandField(step.OperationID) {
			reasons = append(reasons, "command_like_field")
			decision = "denied"
		}
		if _, ok := planned.Descriptor(step.OperationID, step.OperationVersion); !ok {
			if _, ok := readopsLookup(step.OperationID, step.OperationVersion); ok {
				reasons = append(reasons, "read_only_operation_not_plannable")
				decision = "denied"
			} else {
				reasons = append(reasons, "unknown_operation")
				decision = "denied"
			}
		} else {
			desc, _ := planned.Descriptor(step.OperationID, step.OperationVersion)
			if desc.RiskClass == domain.RiskReadOnly || desc.MutationClass == "none" {
				reasons = append(reasons, "operation_not_mutating")
				decision = "denied"
			}
			if !desc.RequiresExplicitApproval {
				reasons = append(reasons, "operation_missing_approval_flag")
				decision = "denied"
			}
			if !desc.RequiresBackup {
				reasons = append(reasons, "operation_missing_backup_flag")
				decision = "denied"
			}
		}
		if !step.ApprovalRequired || !step.BackupRequired {
			reasons = append(reasons, "step_missing_required_flags")
			decision = "denied"
		}
	}
	if len(plan.BackupRequirements) == 0 {
		reasons = append(reasons, "backup_requirements_missing")
		decision = "denied"
	}
	if len(plan.ApprovalRequirements) == 0 {
		reasons = append(reasons, "approval_requirements_missing")
		decision = "denied"
	}
	hasVerify := false
	for _, b := range plan.BackupRequirements {
		if strings.HasPrefix(b, "verify:") {
			hasVerify = true
			break
		}
	}
	if !hasVerify {
		reasons = append(reasons, "verification_requirements_missing")
		decision = "denied"
	}

	topoID := ""
	for _, e := range snap.EvidenceBundles {
		if e.FactsSchema == domain.SchemaWindowsBootTopology {
			var topo domain.WindowsBootTopology
			if err := json.Unmarshal(e.Facts, &topo); err == nil {
				topoID = topo.TopologyID
				for _, b := range topo.MutationEligibility.Blockers {
					reasons = append(reasons, "topology_blocker_"+b)
					decision = "denied"
				}
				if topo.FirmwareMode != domain.FirmwareUEFI {
					reasons = append(reasons, "firmware_not_uefi")
					decision = "denied"
				}
			} else {
				reasons = append(reasons, "topology_unreadable")
				decision = "needs_more_evidence"
			}
		}
	}
	if topoID == "" {
		reasons = append(reasons, "topology_missing")
		decision = "needs_more_evidence"
	}

	reasons = uniqueSorted(reasons)
	if len(reasons) == 0 {
		reasons = []string{"policy_gates_passed"}
	}
	planDigest, err := DigestPlan(plan)
	if err != nil {
		return domain.PolicyEvaluation{}, err
	}
	inputDigest := sha256Hex(fmt.Sprintf("policy|%s|%s|%s|%s", PolicyVersion, plan.PlanID, planDigest, sourceCommitID))
	evalID := "pol-" + sha256Hex(fmt.Sprintf("pol|%s|%s|%s", snap.Case.CaseID, requestID, inputDigest))[:24]
	ev := domain.PolicyEvaluation{
		SchemaName:     domain.SchemaPolicyEvaluation,
		SchemaVersion:  domain.SchemaVersion,
		EvaluationID:   evalID,
		CaseID:         snap.Case.CaseID,
		RequestID:      requestID,
		PlanID:         plan.PlanID,
		PlanDigest:     planDigest,
		SourceCommitID: sourceCommitID,
		TopologyID:     topoID,
		EvaluatedAt:    now.UTC().Format(time.RFC3339),
		Decision:       decision,
		ReasonCodes:    reasons,
		PolicyVersion:  PolicyVersion,
		InputDigest:    inputDigest,
		Limitations: []string{
			"Policy allowed does not authorize execution.",
			"Backup and typed executor gates remain required after approval.",
			"Agent consultation is advisory and is never sufficient alone.",
		},
	}
	if err := ev.Validate(); err != nil {
		return domain.PolicyEvaluation{}, err
	}
	return ev, nil
}

// DigestPlan returns a canonical SHA-256 of identity-bearing plan fields.
func DigestPlan(plan domain.RepairPlan) (string, error) {
	type identity struct {
		PlanID               string            `json:"plan_id"`
		CaseID               string            `json:"case_id"`
		FindingRefs          []string          `json:"finding_refs"`
		Steps                []domain.PlanStep `json:"steps"`
		RiskSummary          string            `json:"risk_summary"`
		BackupRequirements   []string          `json:"backup_requirements"`
		ApprovalRequirements []string          `json:"approval_requirements"`
		Status               string            `json:"status"`
	}
	payload := identity{
		PlanID: plan.PlanID, CaseID: plan.CaseID, FindingRefs: append([]string(nil), plan.FindingRefs...),
		Steps: plan.Steps, RiskSummary: plan.RiskSummary,
		BackupRequirements:   append([]string(nil), plan.BackupRequirements...),
		ApprovalRequirements: append([]string(nil), plan.ApprovalRequirements...),
		Status:               plan.Status,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return sha256Hex(string(raw)), nil
}

// DigestEvaluation returns identity digest for an evaluation (ignores evaluated_at).
func DigestEvaluation(ev domain.PolicyEvaluation) (string, error) {
	type identity struct {
		EvaluationID   string   `json:"evaluation_id"`
		CaseID         string   `json:"case_id"`
		RequestID      string   `json:"request_id"`
		PlanID         string   `json:"plan_id"`
		PlanDigest     string   `json:"plan_digest"`
		SourceCommitID string   `json:"source_commit_id"`
		Decision       string   `json:"decision"`
		ReasonCodes    []string `json:"reason_codes"`
		PolicyVersion  string   `json:"policy_version"`
		InputDigest    string   `json:"input_digest"`
		Limitations    []string `json:"limitations"`
	}
	payload := identity{
		EvaluationID: ev.EvaluationID, CaseID: ev.CaseID, RequestID: ev.RequestID,
		PlanID: ev.PlanID, PlanDigest: ev.PlanDigest, SourceCommitID: ev.SourceCommitID,
		Decision: ev.Decision, ReasonCodes: append([]string(nil), ev.ReasonCodes...),
		PolicyVersion: ev.PolicyVersion, InputDigest: ev.InputDigest,
		Limitations: append([]string(nil), ev.Limitations...),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return sha256Hex(string(raw)), nil
}

func readopsLookup(operationID, version string) (domain.OperationDescriptor, bool) {
	reg, err := readops.NewRegistry()
	if err != nil {
		return domain.OperationDescriptor{}, false
	}
	return reg.Descriptor(operationID, version)
}

func containsCommandField(v string) bool {
	lower := strings.ToLower(v)
	for _, bad := range []string{"powershell", "cmd.exe", "diskpart", "argv", "script"} {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

func uniqueSorted(in []string) []string {
	set := map[string]struct{}{}
	for _, v := range in {
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func planStepCycle(steps []domain.PlanStep) bool {
	if len(steps) == 0 {
		return false
	}
	graph := make(map[string][]string, len(steps))
	for _, step := range steps {
		graph[step.StepID] = append([]string(nil), step.DependsOn...)
	}
	visited := make(map[string]int, len(steps))
	var visit func(id string) bool
	visit = func(id string) bool {
		switch visited[id] {
		case 1:
			return true
		case 2:
			return false
		}
		visited[id] = 1
		for _, dep := range graph[id] {
			if visit(dep) {
				return true
			}
		}
		visited[id] = 2
		return false
	}
	for id := range graph {
		if visit(id) {
			return true
		}
	}
	return false
}
