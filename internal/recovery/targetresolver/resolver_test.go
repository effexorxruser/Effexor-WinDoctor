package targetresolver_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/targetresolver"
)

func TestResolveDeterministicHappyPath(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "uefi", true)
	req := targetresolver.Request{
		Snapshot: snap,
		CommitID: "commit-111111111111111111111111",
		Now:      time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC),
	}
	a, err := targetresolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := targetresolver.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if a.Topology.TopologyID != b.Topology.TopologyID {
		t.Fatalf("topology id nondeterministic: %s vs %s", a.Topology.TopologyID, b.Topology.TopologyID)
	}
	if a.Evidence.EvidenceID != b.Evidence.EvidenceID {
		t.Fatalf("evidence id nondeterministic")
	}
	if a.Topology.FirmwareMode != domain.FirmwareUEFI {
		t.Fatalf("firmware %s", a.Topology.FirmwareMode)
	}
}

func TestDriveLetterRelationNeverProven(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "uefi", true)
	for i := range snap.Targets {
		if snap.Targets[i].TargetType == "windows_installation" || snap.Targets[i].TargetType == "partition" {
			if snap.Targets[i].RuntimeLocators == nil {
				snap.Targets[i].RuntimeLocators = map[string]string{}
			}
			snap.Targets[i].RuntimeLocators["drive_letter"] = "C:"
		}
	}
	res, err := targetresolver.Resolve(context.Background(), targetresolver.Request{
		Snapshot: snap, CommitID: "commit-111111111111111111111111",
		Now: time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range res.Topology.Relations {
		if rel.RelationType == domain.RelationHostsWindows && rel.Confidence == domain.ConfidenceProven {
			t.Fatalf("drive-letter relation must not be proven: %+v", rel)
		}
	}
}

func TestConflictingFirmware(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "uefi", true)
	for i, e := range snap.EvidenceBundles {
		if e.TargetID == "target-firmware-system" {
			var env map[string]any
			if err := json.Unmarshal(e.Facts, &env); err != nil {
				t.Fatal(err)
			}
			payload := env["payload"].(map[string]any)
			payload["boot_firmware_mode"] = "uefi"
			payload["hardware"] = map[string]any{"firmware_mode": "bios"}
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			snap.EvidenceBundles[i].Facts = raw
		}
	}
	res, err := targetresolver.Resolve(context.Background(), targetresolver.Request{
		Snapshot: snap, CommitID: "commit-111111111111111111111111",
		Now: time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Topology.FirmwareMode != domain.FirmwareConflicting {
		t.Fatalf("got %s", res.Topology.FirmwareMode)
	}
	if res.Topology.MutationEligibility.Eligible {
		t.Fatal("conflicting firmware must not be eligible")
	}
}

func TestBIOSMBRBlocksAutomatic(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "bios", false)
	res, err := targetresolver.Resolve(context.Background(), targetresolver.Request{
		Snapshot: snap, CommitID: "commit-111111111111111111111111",
		Now: time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Topology.Selection.Source != domain.SelectionNone {
		t.Fatalf("selection %s", res.Topology.Selection.Source)
	}
}

func TestESPGUIDNormalization(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "uefi", true)
	res, err := targetresolver.Resolve(context.Background(), targetresolver.Request{
		Snapshot: snap, CommitID: "commit-111111111111111111111111",
		Now: time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range res.Topology.Candidates {
		if c.Role == domain.RoleEFISystemPartition {
			found = true
		}
	}
	if !found {
		t.Fatal("ESP candidate missing for braced uppercase GPT GUID")
	}
}

func topologySnapshot(t *testing.T, firmware string, gpt bool) casestore.Snapshot {
	t.Helper()
	firmwareID := "target-firmware-system"
	diskID := "target-disk-nvme0n1"
	partID := "target-part-windows-01"
	espID := "target-part-esp-01"
	winID := "target-windows-install-01"
	bcdID := "target-bcd-store-01"
	style := "GPT"
	if !gpt {
		style = "MBR"
	}
	snap := casestore.Snapshot{
		Case: domain.CaseManifest{
			SchemaName: domain.SchemaCaseManifest, SchemaVersion: domain.SchemaVersion,
			CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: "2026-07-27T12:00:00Z",
			UpdatedAt: "2026-07-27T12:05:00Z", Runtime: "winpe", CurrentState: domain.CaseStateSnapshotted,
			TargetIDs: []string{firmwareID, diskID, partID, espID, winID, bcdID}, PrivacyClass: "standard",
		},
		Targets: []domain.Target{
			target(firmwareID, "firmware", "Firmware", nil),
			target(diskID, "disk", "Disk 0", map[string]string{"disk_number": "0", "partition_style": style}),
			target(partID, "partition", "Windows", map[string]string{"disk_number": "0"}),
			target(espID, "partition", "ESP", map[string]string{"disk_number": "0"}),
			target(winID, "windows_installation", "Windows", nil),
			target(bcdID, "boot_store", "BCD", nil),
		},
		EvidenceBundles: []domain.EvidenceBundle{
			legacyBundle(t, "evidence-bbbbbbbbbbbbbbbbbbbbbbbb", firmwareID, "firmware_environment", map[string]any{
				"boot_firmware_mode": firmware, "hardware": map[string]any{"firmware_mode": firmware}, "drive_health": []any{},
			}, nil),
			legacyBundle(t, "evidence-cccccccccccccccccccccccc", diskID, "disk", map[string]any{
				"disk_number": json.Number("0"), "partition_style": style,
			}, nil),
			legacyBundle(t, "evidence-dddddddddddddddddddddddd", partID, "partition", map[string]any{
				"disk_number": json.Number("0"), "type": "Basic",
			}, []string{diskID}),
			legacyBundle(t, "evidence-eeeeeeeeeeeeeeeeeeeeeeee", espID, "partition", map[string]any{
				"disk_number": json.Number("0"), "gpt_type": "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}",
			}, []string{diskID}),
			legacyBundle(t, "evidence-ffffffffffffffffffffffff", winID, "windows_installation", map[string]any{
				"root_path": `C:\Windows`, "version": "10.0",
			}, []string{partID}),
			legacyBundle(t, "evidence-111111111111111111111111", bcdID, "boot_store", map[string]any{
				"kind": "system", "path": `\EFI\Microsoft\Boot\BCD`,
			}, []string{espID}),
		},
		WorkflowState: &domain.CaseWorkflowState{
			SchemaName: domain.SchemaCaseWorkflowState, SchemaVersion: domain.SchemaVersion,
			CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa", State: domain.WorkflowEvidenceCollected,
			Revision: 1, UpdatedAt: "2026-07-27T12:05:00Z", LastTransitionID: "cevt-111111111111111111111111",
		},
		CoordinatorEvents: []domain.CoordinatorEvent{{
			SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
			EventID: "cevt-111111111111111111111111", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			EventType: domain.EventCaseCreated, ActorType: domain.ActorSystem,
			OccurredAt: "2026-07-27T12:05:00Z", PreviousState: string(domain.WorkflowCreated),
			NextState: string(domain.WorkflowEvidenceCollected), WorkflowRevision: 1,
			ReferencedDocumentIDs: []string{
				"case-aaaaaaaaaaaaaaaaaaaaaaaa", firmwareID, diskID, partID, espID, winID, bcdID,
				"evidence-bbbbbbbbbbbbbbbbbbbbbbbb", "evidence-cccccccccccccccccccccccc",
				"evidence-dddddddddddddddddddddddd", "evidence-eeeeeeeeeeeeeeeeeeeeeeee",
				"evidence-ffffffffffffffffffffffff", "evidence-111111111111111111111111",
				domain.DocumentIDCaseWorkflowState,
			},
			ReasonCode: "legacy_import_committed",
		}},
	}
	if err := snap.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return snap
}

func target(id, typ, name string, loc map[string]string) domain.Target {
	if loc == nil {
		loc = map[string]string{}
	}
	return domain.Target{
		SchemaName: domain.SchemaTarget, SchemaVersion: domain.SchemaVersion,
		TargetID: id, TargetType: typ, DiscoveredAt: "2026-07-27T12:00:00Z", DisplayName: name,
		StableIdentity: map[string]string{"report_path": id}, RuntimeLocators: loc,
		Capabilities: []string{"legacy_evidence_available"}, Limitations: []string{},
	}
}

func legacyBundle(t *testing.T, evidenceID, targetID, kind string, payload map[string]any, related []string) domain.EvidenceBundle {
	t.Helper()
	if related == nil {
		related = []string{}
	}
	env := map[string]any{
		"schema_name": "legacy-diagnostic-report-fragment", "schema_version": "1.0.0",
		"source_schema_name": "diagnostic-report", "source_schema_version": "1.3.0",
		"source_report_id":         "report000000000001",
		"raw_source_sha256":        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"normalized_report_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"source_collector":         "effexorwinpe-collector", "source_collector_version": "0.1.0",
		"source_path": kind, "entity_kind": kind, "payload": payload,
		"related_target_ids": related, "limitations": []string{},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return domain.EvidenceBundle{
		SchemaName: domain.SchemaEvidenceBundle, SchemaVersion: domain.SchemaVersion,
		EvidenceID: evidenceID, CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa", TargetID: targetID,
		Collector: "legacy", CollectorVersion: "1.0.0", CapturedAt: "2026-07-27T12:00:00Z",
		SourceStatus: "ok", FactsSchema: legacyreport.FactsSchemaID, Facts: raw,
		Artifacts: []domain.ArtifactRef{}, Limitations: []string{},
	}
}
