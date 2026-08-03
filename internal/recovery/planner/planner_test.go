package planner_test

import (
	"encoding/json"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/planner"
)

func TestPlanRefusesWithoutAnalyzed(t *testing.T) {
	t.Parallel()
	snap := analyzedTopologySnapshot(t)
	snap.WorkflowState.State = domain.WorkflowEvidenceCollected
	snap.Case.CurrentState = domain.CaseStateSnapshotted
	res, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if res.Refusal == nil {
		t.Fatal("expected refusal")
	}
}

func TestPlanHappyPathEligibleTopologyAndBCDFinding(t *testing.T) {
	t.Parallel()
	snap := analyzedTopologySnapshot(t)
	res, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if res.Refusal != nil {
		t.Fatalf("unexpected refusal: %v", res.Refusal)
	}
	if res.Plan == nil || len(res.Plan.Steps) != 1 || res.Plan.PlanID == "" {
		t.Fatalf("unexpected plan: %#v", res.Plan)
	}
}

func TestPlanDeterministic(t *testing.T) {
	t.Parallel()
	snap := analyzedTopologySnapshot(t)
	a, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || a.Refusal != nil {
		t.Fatalf("err=%v refusal=%v", err, a.Refusal)
	}
	b, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || b.Refusal != nil {
		t.Fatalf("err=%v refusal=%v", err, b.Refusal)
	}
	if a.Plan.PlanID != b.Plan.PlanID {
		t.Fatalf("plan id drift: %s vs %s", a.Plan.PlanID, b.Plan.PlanID)
	}
}

func TestPlanRefusesTopologyBlockers(t *testing.T) {
	t.Parallel()
	snap := analyzedTopologySnapshot(t)
	mutateTopology(t, &snap, func(topo *domain.WindowsBootTopology) {
		topo.MutationEligibility.Eligible = false
		topo.MutationEligibility.Blockers = []string{"bitlocker_inaccessible"}
	})
	res, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if res.Refusal == nil {
		t.Fatal("expected refusal for topology blockers")
	}
}

func TestPlanRefusesLegacyBIOS(t *testing.T) {
	t.Parallel()
	snap := analyzedTopologySnapshot(t)
	mutateTopology(t, &snap, func(topo *domain.WindowsBootTopology) {
		topo.FirmwareMode = domain.FirmwareBIOS
		topo.MutationEligibility.Eligible = false
		topo.MutationEligibility.Blockers = []string{"firmware_not_uefi", "disk_not_gpt"}
	})
	res, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if res.Refusal == nil {
		t.Fatal("expected Legacy/BIOS refusal")
	}
}

func TestPlanWorksWithoutConsultation(t *testing.T) {
	t.Parallel()
	snap := analyzedTopologySnapshot(t)
	if len(snap.AgentConsultations) != 0 {
		t.Fatal("fixture must not require consultation")
	}
	res, err := planner.Plan(snap, "commit-111111111111111111111111")
	if err != nil || res.Refusal != nil {
		t.Fatalf("err=%v refusal=%v", err, res.Refusal)
	}
}

func analyzedTopologySnapshot(t *testing.T) casestore.Snapshot {
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

	topo := eligibleUEFITopology(caseID, firmwareID, diskID, partID, espID, winID, bcdID)
	topoRaw, err := json.Marshal(topo)
	if err != nil {
		t.Fatal(err)
	}

	finding := domain.Finding{
		SchemaName: domain.SchemaFinding, SchemaVersion: domain.SchemaVersion,
		FindingID: findingID, CaseID: caseID,
		Severity: "medium", Confidence: "medium", Title: "BCD membership unknown",
		Rationale:            "Synthetic BCD repair finding for planner tests.",
		EvidenceRefs:         []string{topoEvidenceID},
		AffectedTargetIDs:    []string{bcdID},
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
				ReferencedDocumentIDs: uniqueStrings(caseID, domain.DocumentIDCaseWorkflowState, findingID, topoEvidenceID, bcdID),
			},
		},
	}
	snap.Normalize()
	if err := snap.Validate(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return snap
}

func eligibleUEFITopology(caseID, firmwareID, diskID, partID, espID, winID, bcdID string) domain.WindowsBootTopology {
	return domain.WindowsBootTopology{
		SchemaName: domain.SchemaWindowsBootTopology, SchemaVersion: domain.SchemaVersion,
		TopologyID: "topology-aaaaaaaaaaaaaaaaaaaaaaaa", CaseID: caseID,
		ResolverID: "effexor-recovery-target-resolver", ResolverVersion: "1.0.0",
		SourceCommitID: "commit-111111111111111111111111", GeneratedAt: "2026-07-27T12:10:00Z",
		FirmwareMode: domain.FirmwareUEFI,
		Candidates: []domain.TopologyCandidate{
			cand("cand.firmware.1", domain.RoleFirmware, firmwareID, "evidence-bbbbbbbbbbbbbbbbbbbbbbbb"),
			cand("cand.disk.1", domain.RoleSystemDisk, diskID, "evidence-cccccccccccccccccccccccc"),
			cand("cand.winpart.1", domain.RoleWindowsPartition, partID, "evidence-dddddddddddddddddddddddd"),
			cand("cand.esp.1", domain.RoleEFISystemPartition, espID, "evidence-eeeeeeeeeeeeeeeeeeeeeeee"),
			cand("cand.win.1", domain.RoleWindowsInstallation, winID, "evidence-ffffffffffffffffffffffff"),
			cand("cand.bcd.1", domain.RoleBCDStore, bcdID, "evidence-111111111111111111111111"),
		},
		Relations: []domain.TopologyRelation{
			{
				RelationID: "rel.hosts.windows.1", RelationType: domain.RelationHostsWindows,
				FromTargetID: diskID, ToTargetID: winID, Confidence: domain.ConfidenceProven,
				EvidenceRefs: []string{"evidence-ffffffffffffffffffffffff"}, RationaleCodes: []string{"single_windows"}, Limitations: []string{},
			},
			{
				RelationID: "rel.hosts.esp.1", RelationType: domain.RelationHostsESP,
				FromTargetID: diskID, ToTargetID: espID, Confidence: domain.ConfidenceProven,
				EvidenceRefs: []string{"evidence-eeeeeeeeeeeeeeeeeeeeeeee"}, RationaleCodes: []string{"single_esp"}, Limitations: []string{},
			},
			{
				RelationID: "rel.contains.bcd.1", RelationType: domain.RelationContainsBCDStore,
				FromTargetID: espID, ToTargetID: bcdID, Confidence: domain.ConfidenceProven,
				EvidenceRefs: []string{"evidence-111111111111111111111111"}, RationaleCodes: []string{"bcd_on_esp"}, Limitations: []string{},
			},
		},
		Selection: domain.TopologySelection{
			Source:                   domain.SelectionAutomatic,
			WindowsTargetID:          winID,
			WindowsPartitionTargetID: partID,
			SystemDiskTargetID:       diskID,
			ESPTargetID:              espID,
			BCDTargetID:              bcdID,
		},
		Ambiguities: []domain.TopologyAmbiguity{},
		Limitations: []string{"planner_fixture"},
		MutationEligibility: domain.MutationEligibility{
			Eligible: true, Basis: domain.MutationEligibilityDiagnosticEvidenceOnly, Blockers: []string{},
		},
	}
}

func cand(id string, role domain.TopologyRole, targetID, evidenceID string) domain.TopologyCandidate {
	return domain.TopologyCandidate{
		CandidateID: id, Role: role, TargetID: targetID, Confidence: domain.ConfidenceProven,
		EvidenceRefs: []string{evidenceID}, RationaleCodes: []string{"fixture"}, Limitations: []string{},
	}
}

func mutateTopology(t *testing.T, snap *casestore.Snapshot, fn func(*domain.WindowsBootTopology)) {
	t.Helper()
	for i := range snap.EvidenceBundles {
		if snap.EvidenceBundles[i].FactsSchema != domain.SchemaWindowsBootTopology {
			continue
		}
		var topo domain.WindowsBootTopology
		if err := json.Unmarshal(snap.EvidenceBundles[i].Facts, &topo); err != nil {
			t.Fatal(err)
		}
		fn(&topo)
		raw, err := json.Marshal(topo)
		if err != nil {
			t.Fatal(err)
		}
		snap.EvidenceBundles[i].Facts = raw
	}
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

func uniqueStrings(ids ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
