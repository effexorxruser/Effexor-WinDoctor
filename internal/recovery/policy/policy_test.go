package policy_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/planner"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/policy"
)

func TestEvaluateAllowsValidPlan(t *testing.T) {
	t.Parallel()
	snap := analyzedPlanningSnapshot(t)
	planRes, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || planRes.Refusal != nil || planRes.Plan == nil {
		t.Fatalf("plan: %v refusal=%v", err, planRes.Refusal)
	}
	ev, err := policy.Evaluate(snap, *planRes.Plan, "commit-111111111111111111111111", "polreq-aaaaaaaaaaaaaaaaaaaaaaaa", time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decision != "allowed" {
		t.Fatalf("decision=%s reasons=%v", ev.Decision, ev.ReasonCodes)
	}
}

func TestEvaluateDeniesUnknownOperation(t *testing.T) {
	t.Parallel()
	snap := analyzedPlanningSnapshot(t)
	planRes, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || planRes.Refusal != nil {
		t.Fatal(err)
	}
	plan := *planRes.Plan
	plan.Steps[0].OperationID = "boot.not_a_real_op"
	ev, err := policy.Evaluate(snap, plan, "commit-111111111111111111111111", "polreq-bbbbbbbbbbbbbbbbbbbbbbbb", time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decision != "denied" {
		t.Fatalf("decision=%s reasons=%v", ev.Decision, ev.ReasonCodes)
	}
}

func TestEvaluateDeniesMissingBackup(t *testing.T) {
	t.Parallel()
	snap := analyzedPlanningSnapshot(t)
	planRes, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || planRes.Refusal != nil {
		t.Fatal(err)
	}
	plan := *planRes.Plan
	plan.BackupRequirements = []string{}
	ev, err := policy.Evaluate(snap, plan, "commit-111111111111111111111111", "polreq-cccccccccccccccccccccccc", time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decision != "denied" {
		t.Fatalf("decision=%s", ev.Decision)
	}
}

func TestEvaluateDeniesTopologyBlocker(t *testing.T) {
	t.Parallel()
	snap := analyzedPlanningSnapshot(t)
	for i := range snap.EvidenceBundles {
		if snap.EvidenceBundles[i].FactsSchema != domain.SchemaWindowsBootTopology {
			continue
		}
		var topo domain.WindowsBootTopology
		if err := json.Unmarshal(snap.EvidenceBundles[i].Facts, &topo); err != nil {
			t.Fatal(err)
		}
		topo.MutationEligibility.Eligible = false
		topo.MutationEligibility.Blockers = []string{"storage_health_unsafe"}
		raw, err := json.Marshal(topo)
		if err != nil {
			t.Fatal(err)
		}
		snap.EvidenceBundles[i].Facts = raw
	}
	planRes, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if planRes.Refusal == nil {
		t.Fatal("planner should refuse blocked topology before policy")
	}
}

func TestDigestPlanStable(t *testing.T) {
	t.Parallel()
	snap := analyzedPlanningSnapshot(t)
	planRes, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || planRes.Plan == nil {
		t.Fatal(err)
	}
	a, err := policy.DigestPlan(*planRes.Plan)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.DigestPlan(*planRes.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("plan digest not stable")
	}
}

func analyzedPlanningSnapshot(t *testing.T) casestore.Snapshot {
	t.Helper()
	firmwareID := "target-firmware-system"
	diskID := "target-disk-nvme0n1"
	partID := "target-part-windows-01"
	espID := "target-part-esp-01"
	winID := "target-windows-install-01"
	bcdID := "target-bcd-store-01"
	caseID := "case-aaaaaaaaaaaaaaaaaaaaaaaa"
	topoEvidenceID := "evidence-75a2ff534d45622a0273b491"
	findingID := "finding-bbbbbbbbbbbbbbbbbbbbbbbb"

	topo := domain.WindowsBootTopology{
		SchemaName: domain.SchemaWindowsBootTopology, SchemaVersion: domain.SchemaVersion,
		TopologyID: "topology-aaaaaaaaaaaaaaaaaaaaaaaa", CaseID: caseID,
		ResolverID: "effexor-recovery-target-resolver", ResolverVersion: "1.0.0",
		SourceCommitID: "commit-111111111111111111111111", GeneratedAt: "2026-07-27T12:10:00Z",
		FirmwareMode: domain.FirmwareUEFI,
		Candidates: []domain.TopologyCandidate{
			{CandidateID: "cand.firmware.1", Role: domain.RoleFirmware, TargetID: firmwareID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"}, RationaleCodes: []string{"fixture"}, Limitations: []string{}},
			{CandidateID: "cand.disk.1", Role: domain.RoleSystemDisk, TargetID: diskID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-cccccccccccccccccccccccc"}, RationaleCodes: []string{"fixture"}, Limitations: []string{}},
			{CandidateID: "cand.winpart.1", Role: domain.RoleWindowsPartition, TargetID: partID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-dddddddddddddddddddddddd"}, RationaleCodes: []string{"fixture"}, Limitations: []string{}},
			{CandidateID: "cand.esp.1", Role: domain.RoleEFISystemPartition, TargetID: espID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-eeeeeeeeeeeeeeeeeeeeeeee"}, RationaleCodes: []string{"fixture"}, Limitations: []string{}},
			{CandidateID: "cand.win.1", Role: domain.RoleWindowsInstallation, TargetID: winID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-ffffffffffffffffffffffff"}, RationaleCodes: []string{"fixture"}, Limitations: []string{}},
			{CandidateID: "cand.bcd.1", Role: domain.RoleBCDStore, TargetID: bcdID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-111111111111111111111111"}, RationaleCodes: []string{"fixture"}, Limitations: []string{}},
		},
		Relations: []domain.TopologyRelation{
			{RelationID: "rel.hosts.windows.1", RelationType: domain.RelationHostsWindows, FromTargetID: diskID, ToTargetID: winID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-ffffffffffffffffffffffff"}, RationaleCodes: []string{"single_windows"}, Limitations: []string{}},
			{RelationID: "rel.hosts.esp.1", RelationType: domain.RelationHostsESP, FromTargetID: diskID, ToTargetID: espID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-eeeeeeeeeeeeeeeeeeeeeeee"}, RationaleCodes: []string{"single_esp"}, Limitations: []string{}},
			{RelationID: "rel.contains.bcd.1", RelationType: domain.RelationContainsBCDStore, FromTargetID: espID, ToTargetID: bcdID, Confidence: domain.ConfidenceProven, EvidenceRefs: []string{"evidence-111111111111111111111111"}, RationaleCodes: []string{"bcd_on_esp"}, Limitations: []string{}},
		},
		Selection: domain.TopologySelection{
			Source: domain.SelectionAutomatic, WindowsTargetID: winID, WindowsPartitionTargetID: partID,
			SystemDiskTargetID: diskID, ESPTargetID: espID, BCDTargetID: bcdID,
		},
		Ambiguities: []domain.TopologyAmbiguity{},
		Limitations: []string{"policy_fixture"},
		MutationEligibility: domain.MutationEligibility{
			Eligible: true, Basis: domain.MutationEligibilityDiagnosticEvidenceOnly, Blockers: []string{},
		},
	}
	topoRaw, err := json.Marshal(topo)
	if err != nil {
		t.Fatal(err)
	}
	finding := domain.Finding{
		SchemaName: domain.SchemaFinding, SchemaVersion: domain.SchemaVersion,
		FindingID: findingID, CaseID: caseID, Severity: "medium", Confidence: "medium",
		Title: "BCD membership unknown", Rationale: "Synthetic BCD repair finding for policy tests.",
		EvidenceRefs: []string{topoEvidenceID}, AffectedTargetIDs: []string{bcdID},
		RecommendedWorkflows: []string{"boot.inspect_bcd_membership"},
		Limitations:          []string{"finding_code:" + bootdoctor.CodeBCDMembershipUnknown},
	}
	snap := casestore.Snapshot{
		Case: domain.CaseManifest{
			SchemaName: domain.SchemaCaseManifest, SchemaVersion: domain.SchemaVersion,
			CaseID: caseID, CreatedAt: "2026-07-27T12:00:00Z", UpdatedAt: "2026-07-27T12:10:00Z",
			Runtime: "winpe", CurrentState: domain.CaseStateDiagnosed,
			TargetIDs: []string{firmwareID, diskID, partID, espID, winID, bcdID}, PrivacyClass: "standard",
		},
		Targets: []domain.Target{
			mkTarget(firmwareID, "firmware", "Firmware", nil),
			mkTarget(diskID, "disk", "Disk 0", map[string]string{"disk_number": "0", "partition_style": "GPT"}),
			mkTarget(partID, "partition", "Windows", map[string]string{"disk_number": "0"}),
			mkTarget(espID, "partition", "ESP", map[string]string{"disk_number": "0"}),
			mkTarget(winID, "windows_installation", "Windows", nil),
			mkTarget(bcdID, "boot_store", "BCD", nil),
		},
		EvidenceBundles: []domain.EvidenceBundle{
			legacyEvidence("evidence-bbbbbbbbbbbbbbbbbbbbbbbb", caseID, firmwareID),
			legacyEvidence("evidence-cccccccccccccccccccccccc", caseID, diskID),
			legacyEvidence("evidence-dddddddddddddddddddddddd", caseID, partID),
			legacyEvidence("evidence-eeeeeeeeeeeeeeeeeeeeeeee", caseID, espID),
			legacyEvidence("evidence-ffffffffffffffffffffffff", caseID, winID),
			legacyEvidence("evidence-111111111111111111111111", caseID, bcdID),
			{
				SchemaName: domain.SchemaEvidenceBundle, SchemaVersion: domain.SchemaVersion,
				EvidenceID: topoEvidenceID, CaseID: caseID, TargetID: firmwareID, Collector: "target-resolver",
				CollectorVersion: "1.0.0", CapturedAt: "2026-07-27T12:10:00Z", SourceStatus: "ok",
				FactsSchema: domain.SchemaWindowsBootTopology, Facts: topoRaw,
				Artifacts: []domain.ArtifactRef{}, Limitations: []string{"fixture"},
			},
		},
		EvidenceAcquisitions: []domain.EvidenceAcquisitionRecord{{
			SchemaName: domain.SchemaEvidenceAcquisitionRecord, SchemaVersion: domain.SchemaVersion,
			AcquisitionID: "acq-aaaaaaaaaaaaaaaaaaaaaaaa", CaseID: caseID,
			RequestID: "acqreq-999999999999999999999999", SourceCommitID: "commit-111111111111111111111111",
			ProducerType: domain.ProducerTargetResolver, ProducerID: "effexor-recovery-target-resolver",
			ProducerVersion: "1.0.0", ActorType: domain.ActorSystem, AcquiredAt: "2026-07-27T12:10:00Z",
			TargetIDs: []string{firmwareID, diskID, partID, espID, winID, bcdID},
			InputEvidenceIDs: []string{
				"evidence-bbbbbbbbbbbbbbbbbbbbbbbb", "evidence-cccccccccccccccccccccccc",
				"evidence-dddddddddddddddddddddddd", "evidence-eeeeeeeeeeeeeeeeeeeeeeee",
				"evidence-ffffffffffffffffffffffff", "evidence-111111111111111111111111",
			},
			AddedEvidenceIDs: []string{topoEvidenceID}, AddedTargetIDs: []string{},
			ParametersSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ResultSHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Limitations:      []string{"test acquisition"},
		}},
		Findings: []domain.Finding{finding},
		WorkflowState: &domain.CaseWorkflowState{
			SchemaName: domain.SchemaCaseWorkflowState, SchemaVersion: domain.SchemaVersion,
			CaseID: caseID, State: domain.WorkflowAnalyzed, Revision: 2,
			UpdatedAt: "2026-07-27T12:10:00Z", LastTransitionID: "cevt-222222222222222222222222",
		},
		CoordinatorEvents: []domain.CoordinatorEvent{
			{
				SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
				EventID: "cevt-111111111111111111111111", CaseID: caseID, EventType: domain.EventCaseCreated,
				ActorType: domain.ActorSystem, OccurredAt: "2026-07-27T12:05:00Z",
				PreviousState: string(domain.WorkflowCreated), NextState: string(domain.WorkflowEvidenceCollected),
				WorkflowRevision: 1, ReasonCode: "legacy_import_committed",
				ReferencedDocumentIDs: []string{
					caseID, firmwareID, diskID, partID, espID, winID, bcdID,
					"evidence-bbbbbbbbbbbbbbbbbbbbbbbb", "evidence-cccccccccccccccccccccccc",
					"evidence-dddddddddddddddddddddddd", "evidence-eeeeeeeeeeeeeeeeeeeeeeee",
					"evidence-ffffffffffffffffffffffff", "evidence-111111111111111111111111",
					domain.DocumentIDCaseWorkflowState,
				},
			},
			{
				SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
				EventID: "cevt-222222222222222222222222", CaseID: caseID,
				EventType: domain.EventAnalysisCommitted, ActorType: domain.ActorDeterministicAnalyzer,
				OccurredAt: "2026-07-27T12:10:00Z", PreviousState: string(domain.WorkflowEvidenceCollected),
				NextState: string(domain.WorkflowAnalyzed), ExpectedCommitID: "commit-111111111111111111111111",
				WorkflowRevision: 2, ReasonCode: "analysis_committed",
				ReferencedDocumentIDs: []string{caseID, domain.DocumentIDCaseWorkflowState, findingID, topoEvidenceID, bcdID},
			},
		},
	}
	snap.Normalize()
	if err := snap.Validate(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return snap
}

func mkTarget(id, typ, name string, locators map[string]string) domain.Target {
	if locators == nil {
		locators = map[string]string{}
	}
	return domain.Target{
		SchemaName: domain.SchemaTarget, SchemaVersion: domain.SchemaVersion,
		TargetID: id, TargetType: typ, DiscoveredAt: "2026-07-27T12:00:00Z", DisplayName: name,
		StableIdentity: map[string]string{"report_path": id}, RuntimeLocators: locators,
		Capabilities: []string{"legacy_evidence_available"}, Limitations: []string{},
	}
}

func legacyEvidence(id, caseID, targetID string) domain.EvidenceBundle {
	return domain.EvidenceBundle{
		SchemaName: domain.SchemaEvidenceBundle, SchemaVersion: domain.SchemaVersion,
		EvidenceID: id, CaseID: caseID, TargetID: targetID, Collector: "legacy",
		CollectorVersion: "1.0.0", CapturedAt: "2026-07-27T12:00:00Z", SourceStatus: "ok",
		FactsSchema: "legacy-diagnostic-report-fragment", Facts: json.RawMessage(`{"schema_name":"legacy-diagnostic-report-fragment","schema_version":"1.0.0","source_schema_name":"diagnostic-report","source_schema_version":"1.3.0","source_report_id":"report000000000001","raw_source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","normalized_report_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_collector":"effexorwinpe-collector","source_collector_version":"0.1.0","source_path":"disk","entity_kind":"disk","payload":{"number":0,"partition_style":"GPT"},"related_target_ids":[],"limitations":[]}`),
		Artifacts: []domain.ArtifactRef{}, Limitations: []string{},
	}
}
