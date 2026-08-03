package bootdoctor_test

import (
	"context"
	"encoding/json"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/targetresolver"
)

const (
	testCaseID  = "case-aaaaaaaaaaaaaaaaaaaaaaaa"
	testCommit  = "commit-111111111111111111111111"
	testNowBase = "2026-07-27T12:10:00Z"
)

var testNow = time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC)

type resolvedFixture struct {
	Snap     casestore.Snapshot
	Topology domain.WindowsBootTopology
	Evidence domain.EvidenceBundle
}

func resolveFixture(t *testing.T, snap casestore.Snapshot, now time.Time) resolvedFixture {
	t.Helper()
	res, err := targetresolver.Resolve(context.Background(), targetresolver.Request{
		Snapshot: snap,
		CommitID: testCommit,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := res.Topology.Validate(); err != nil {
		t.Fatalf("topology invalid: %v", err)
	}
	return resolvedFixture{Snap: snap, Topology: res.Topology, Evidence: res.Evidence}
}

func analyzeFixture(t *testing.T, fix resolvedFixture, topoEvidenceID string) bootdoctor.Result {
	t.Helper()
	in := bootdoctor.Input{
		CaseID:             testCaseID,
		Topology:           fix.Topology,
		TopologyEvidenceID: topoEvidenceID,
		Targets:            fix.Snap.Targets,
		KnownEvidenceIDs:   evidenceIDsFromSnap(fix.Snap),
		KnownTargetIDs:     targetIDsFromSnap(fix.Snap),
	}
	if topoEvidenceID != "" {
		in.KnownEvidenceIDs = append(in.KnownEvidenceIDs, topoEvidenceID)
	}
	res, err := bootdoctor.Analyze(in)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return res
}

func analyzeResolved(t *testing.T, snap casestore.Snapshot) bootdoctor.Result {
	t.Helper()
	fix := resolveFixture(t, snap, testNow)
	return analyzeFixture(t, fix, fix.Evidence.EvidenceID)
}

func findingCodes(findings []domain.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, bootdoctor.FindingCodeOf(f))
	}
	return out
}

func hasFindingCode(findings []domain.Finding, code string) bool {
	for _, f := range findings {
		if bootdoctor.FindingCodeOf(f) == code {
			return true
		}
	}
	return false
}

func assertHasCode(t *testing.T, findings []domain.Finding, code string) {
	t.Helper()
	if !hasFindingCode(findings, code) {
		t.Fatalf("missing finding code %q; have %v", code, findingCodes(findings))
	}
}

func assertLacksCode(t *testing.T, findings []domain.Finding, code string) {
	t.Helper()
	if hasFindingCode(findings, code) {
		t.Fatalf("unexpected finding code %q", code)
	}
}

func evidenceIDsFromSnap(snap casestore.Snapshot) []string {
	out := make([]string, 0, len(snap.EvidenceBundles))
	for _, ev := range snap.EvidenceBundles {
		out = append(out, ev.EvidenceID)
	}
	return out
}

func targetIDsFromSnap(snap casestore.Snapshot) []string {
	out := make([]string, 0, len(snap.Targets))
	for _, tg := range snap.Targets {
		out = append(out, tg.TargetID)
	}
	return out
}

func shuffleTopology(topo domain.WindowsBootTopology, seed int64) domain.WindowsBootTopology {
	rng := rand.New(rand.NewSource(seed))
	cands := append([]domain.TopologyCandidate(nil), topo.Candidates...)
	rels := append([]domain.TopologyRelation(nil), topo.Relations...)
	amb := append([]domain.TopologyAmbiguity(nil), topo.Ambiguities...)
	rng.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	rng.Shuffle(len(rels), func(i, j int) { rels[i], rels[j] = rels[j], rels[i] })
	rng.Shuffle(len(amb), func(i, j int) { amb[i], amb[j] = amb[j], amb[i] })
	topo.Candidates = cands
	topo.Relations = rels
	if amb == nil {
		topo.Ambiguities = []domain.TopologyAmbiguity{}
	} else {
		topo.Ambiguities = amb
	}
	if topo.Limitations == nil {
		topo.Limitations = []string{}
	}
	return topo
}

func syncCreateEventRefs(snap *casestore.Snapshot) {
	if len(snap.CoordinatorEvents) == 0 {
		return
	}
	refs := []string{snap.Case.CaseID, domain.DocumentIDCaseWorkflowState}
	for _, tg := range snap.Targets {
		refs = append(refs, tg.TargetID)
	}
	for _, ev := range snap.EvidenceBundles {
		refs = append(refs, ev.EvidenceID)
	}
	sort.Strings(refs)
	out := make([]string, 0, len(refs))
	for i, id := range refs {
		if i > 0 && refs[i-1] == id {
			continue
		}
		out = append(out, id)
	}
	snap.CoordinatorEvents[0].ReferencedDocumentIDs = out
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
			CaseID: testCaseID, CreatedAt: "2026-07-27T12:00:00Z",
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
				"boot_firmware_mode": firmware, "hardware": map[string]any{"firmware_mode": firmware},
				"drive_health": []any{map[string]any{"device_id": "0", "health_status": "Healthy", "operational_status": "OK"}},
			}, nil),
			legacyBundle(t, "evidence-cccccccccccccccccccccccc", diskID, "disk", map[string]any{
				"number": json.Number("0"), "partition_style": style,
			}, nil),
			legacyBundle(t, "evidence-dddddddddddddddddddddddd", partID, "partition", map[string]any{
				"disk_number": json.Number("0"), "type": "Basic",
			}, []string{diskID}),
			legacyBundle(t, "evidence-eeeeeeeeeeeeeeeeeeeeeeee", espID, "partition", map[string]any{
				"disk_number": json.Number("0"), "gpt_type": "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}",
			}, []string{diskID}),
			legacyBundle(t, "evidence-ffffffffffffffffffffffff", winID, "windows_installation", map[string]any{
				"root": `C:\Windows`, "version": map[string]any{"product_name": "Windows 10", "build": "19045"},
			}, []string{partID}),
			legacyBundle(t, "evidence-111111111111111111111111", bcdID, "boot_store", map[string]any{
				"kind": "system", "path": `\EFI\Microsoft\Boot\BCD`,
			}, []string{espID}),
		},
		WorkflowState: &domain.CaseWorkflowState{
			SchemaName: domain.SchemaCaseWorkflowState, SchemaVersion: domain.SchemaVersion,
			CaseID: testCaseID, State: domain.WorkflowEvidenceCollected,
			Revision: 1, UpdatedAt: "2026-07-27T12:05:00Z", LastTransitionID: "cevt-111111111111111111111111",
		},
		CoordinatorEvents: []domain.CoordinatorEvent{{
			SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
			EventID: "cevt-111111111111111111111111", CaseID: testCaseID,
			EventType: domain.EventCaseCreated, ActorType: domain.ActorSystem,
			OccurredAt: "2026-07-27T12:05:00Z", PreviousState: string(domain.WorkflowCreated),
			NextState: string(domain.WorkflowEvidenceCollected), WorkflowRevision: 1,
			ReferencedDocumentIDs: []string{
				testCaseID, firmwareID, diskID, partID, espID, winID, bcdID,
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

func topologySnapshotDisconnected(t *testing.T) casestore.Snapshot {
	t.Helper()
	firmwareID := "target-firmware-system"
	disk0ID := "target-disk-nvme0n1"
	disk1ID := "target-disk-nvme1n1"
	partID := "target-part-windows-01"
	espID := "target-part-esp-01"
	winID := "target-windows-install-01"
	bcdID := "target-bcd-store-01"
	snap := casestore.Snapshot{
		Case: domain.CaseManifest{
			SchemaName: domain.SchemaCaseManifest, SchemaVersion: domain.SchemaVersion,
			CaseID: testCaseID, CreatedAt: "2026-07-27T12:00:00Z",
			UpdatedAt: "2026-07-27T12:05:00Z", Runtime: "winpe", CurrentState: domain.CaseStateSnapshotted,
			TargetIDs: []string{firmwareID, disk0ID, disk1ID, partID, espID, winID, bcdID}, PrivacyClass: "standard",
		},
		Targets: []domain.Target{
			target(firmwareID, "firmware", "Firmware", nil),
			target(disk0ID, "disk", "Disk 0", map[string]string{"disk_number": "0", "partition_style": "GPT"}),
			target(disk1ID, "disk", "Disk 1", map[string]string{"disk_number": "1", "partition_style": "GPT"}),
			target(partID, "partition", "Windows", map[string]string{"disk_number": "0"}),
			target(espID, "partition", "ESP", map[string]string{"disk_number": "1"}),
			target(winID, "windows_installation", "Windows", nil),
			target(bcdID, "boot_store", "BCD", nil),
		},
		EvidenceBundles: []domain.EvidenceBundle{
			legacyBundle(t, "evidence-bbbbbbbbbbbbbbbbbbbbbbbb", firmwareID, "firmware_environment", map[string]any{
				"boot_firmware_mode": "uefi", "hardware": map[string]any{"firmware_mode": "uefi"},
				"drive_health": []any{map[string]any{"device_id": "0", "health_status": "Healthy", "operational_status": "OK"}},
			}, nil),
			legacyBundle(t, "evidence-cccccccccccccccccccccccc", disk0ID, "disk", map[string]any{
				"number": json.Number("0"), "partition_style": "GPT",
			}, nil),
			legacyBundle(t, "evidence-222222222222222222222222", disk1ID, "disk", map[string]any{
				"number": json.Number("1"), "partition_style": "GPT",
			}, nil),
			legacyBundle(t, "evidence-dddddddddddddddddddddddd", partID, "partition", map[string]any{
				"disk_number": json.Number("0"), "type": "Basic",
			}, []string{disk0ID}),
			legacyBundle(t, "evidence-eeeeeeeeeeeeeeeeeeeeeeee", espID, "partition", map[string]any{
				"disk_number": json.Number("1"), "gpt_type": "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}",
			}, []string{disk1ID}),
			legacyBundle(t, "evidence-ffffffffffffffffffffffff", winID, "windows_installation", map[string]any{
				"root": `C:\Windows`, "version": map[string]any{"product_name": "Windows 10", "build": "19045"},
			}, []string{partID}),
			legacyBundle(t, "evidence-111111111111111111111111", bcdID, "boot_store", map[string]any{
				"kind": "system", "path": `\EFI\Microsoft\Boot\BCD`,
			}, []string{espID}),
		},
		WorkflowState: &domain.CaseWorkflowState{
			SchemaName: domain.SchemaCaseWorkflowState, SchemaVersion: domain.SchemaVersion,
			CaseID: testCaseID, State: domain.WorkflowEvidenceCollected,
			Revision: 1, UpdatedAt: "2026-07-27T12:05:00Z", LastTransitionID: "cevt-111111111111111111111111",
		},
		CoordinatorEvents: []domain.CoordinatorEvent{{
			SchemaName: domain.SchemaCoordinatorEvent, SchemaVersion: domain.SchemaVersion,
			EventID: "cevt-111111111111111111111111", CaseID: testCaseID,
			EventType: domain.EventCaseCreated, ActorType: domain.ActorSystem,
			OccurredAt: "2026-07-27T12:05:00Z", PreviousState: string(domain.WorkflowCreated),
			NextState: string(domain.WorkflowEvidenceCollected), WorkflowRevision: 1,
			ReferencedDocumentIDs: []string{
				testCaseID, firmwareID, disk0ID, disk1ID, partID, espID, winID, bcdID,
				"evidence-bbbbbbbbbbbbbbbbbbbbbbbb", "evidence-cccccccccccccccccccccccc",
				"evidence-222222222222222222222222", "evidence-dddddddddddddddddddddddd",
				"evidence-eeeeeeeeeeeeeeeeeeeeeeee", "evidence-ffffffffffffffffffffffff",
				"evidence-111111111111111111111111", domain.DocumentIDCaseWorkflowState,
			},
			ReasonCode: "legacy_import_committed",
		}},
	}
	if err := snap.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return snap
}

func topologySnapshotWithBitLocker(t *testing.T, lockStatus string) casestore.Snapshot {
	t.Helper()
	snap := topologySnapshot(t, "uefi", true)
	volID := "target-volume-bitlocker-01"
	evID := "evidence-333333333333333333333333"
	snap.Case.TargetIDs = append(snap.Case.TargetIDs, volID)
	snap.Targets = append(snap.Targets, target(volID, "volume", "BitLocker C:", map[string]string{"mount_point": "C:"}))
	snap.EvidenceBundles = append(snap.EvidenceBundles, legacyBundle(t, evID, volID, "bitlocker_volume", map[string]any{
		"mount_point": "C:", "lock_status": lockStatus, "protection_status": lockStatus,
	}, nil))
	syncCreateEventRefs(&snap)
	if err := snap.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return snap
}

func snapshotWithoutWindows(t *testing.T, snap casestore.Snapshot) casestore.Snapshot {
	t.Helper()
	winID := "target-windows-install-01"
	out := snap
	out.Case.TargetIDs = filterStrings(out.Case.TargetIDs, winID)
	out.Targets = filterTargets(out.Targets, winID)
	out.EvidenceBundles = filterEvidence(out.EvidenceBundles, winID, "evidence-ffffffffffffffffffffffff")
	syncCreateEventRefs(&out)
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func snapshotWithSecondWindows(t *testing.T, snap casestore.Snapshot) casestore.Snapshot {
	t.Helper()
	win2ID := "target-windows-install-02"
	part2ID := "target-part-windows-02"
	disk1ID := "target-disk-nvme1n1"
	evDisk1ID := "evidence-777777777777777777777777"
	out := snap
	if !containsString(out.Case.TargetIDs, disk1ID) {
		out.Case.TargetIDs = append(out.Case.TargetIDs, disk1ID)
		out.Targets = append(out.Targets, target(disk1ID, "disk", "Disk 1", map[string]string{"disk_number": "1", "partition_style": "GPT"}))
		out.EvidenceBundles = append(out.EvidenceBundles, legacyBundle(t, evDisk1ID, disk1ID, "disk", map[string]any{
			"number": json.Number("1"), "partition_style": "GPT",
		}, nil))
	}
	out.Case.TargetIDs = append(out.Case.TargetIDs, win2ID, part2ID)
	out.Targets = append(out.Targets,
		target(part2ID, "partition", "Windows 2", map[string]string{"disk_number": "1"}),
		target(win2ID, "windows_installation", "Windows 2", nil),
	)
	out.EvidenceBundles = append(out.EvidenceBundles,
		legacyBundle(t, "evidence-444444444444444444444444", part2ID, "partition", map[string]any{
			"disk_number": json.Number("1"), "type": "Basic",
		}, []string{disk1ID}),
		legacyBundle(t, "evidence-555555555555555555555555", win2ID, "windows_installation", map[string]any{
			"root": `D:\Windows`, "version": map[string]any{"product_name": "Windows 11", "build": "22631"},
		}, []string{part2ID}),
	)
	syncCreateEventRefs(&out)
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func snapshotWithoutESP(t *testing.T, snap casestore.Snapshot) casestore.Snapshot {
	t.Helper()
	espID := "target-part-esp-01"
	bcdID := "target-bcd-store-01"
	out := snap
	out.Case.TargetIDs = filterStrings(out.Case.TargetIDs, espID, bcdID)
	out.Targets = filterTargets(out.Targets, espID, bcdID)
	out.EvidenceBundles = filterEvidence(out.EvidenceBundles, espID, "evidence-eeeeeeeeeeeeeeeeeeeeeeee", bcdID, "evidence-111111111111111111111111")
	syncCreateEventRefs(&out)
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func snapshotWithSecondESP(t *testing.T, snap casestore.Snapshot) casestore.Snapshot {
	t.Helper()
	esp2ID := "target-part-esp-02"
	diskID := "target-disk-nvme0n1"
	out := snap
	out.Case.TargetIDs = append(out.Case.TargetIDs, esp2ID)
	out.Targets = append(out.Targets, target(esp2ID, "partition", "ESP 2", map[string]string{"disk_number": "0"}))
	out.EvidenceBundles = append(out.EvidenceBundles, legacyBundle(t, "evidence-666666666666666666666666", esp2ID, "partition", map[string]any{
		"disk_number": json.Number("0"), "gpt_type": "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}",
	}, []string{diskID}))
	syncCreateEventRefs(&out)
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func snapshotWithoutDriveHealth(t *testing.T, snap casestore.Snapshot) casestore.Snapshot {
	t.Helper()
	out := snap
	for i, ev := range out.EvidenceBundles {
		if ev.TargetID != "target-firmware-system" {
			continue
		}
		var env map[string]any
		if err := json.Unmarshal(ev.Facts, &env); err != nil {
			t.Fatal(err)
		}
		payload := env["payload"].(map[string]any)
		delete(payload, "drive_health")
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		out.EvidenceBundles[i].Facts = raw
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func snapshotWithConflictingFirmware(t *testing.T, snap casestore.Snapshot) casestore.Snapshot {
	t.Helper()
	out := snap
	for i, ev := range out.EvidenceBundles {
		if ev.TargetID != "target-firmware-system" {
			continue
		}
		var env map[string]any
		if err := json.Unmarshal(ev.Facts, &env); err != nil {
			t.Fatal(err)
		}
		payload := env["payload"].(map[string]any)
		payload["boot_firmware_mode"] = "uefi"
		payload["hardware"] = map[string]any{"firmware_mode": "bios"}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		out.EvidenceBundles[i].Facts = raw
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func snapshotWithStorageHealth(t *testing.T, snap casestore.Snapshot, records []map[string]any) casestore.Snapshot {
	t.Helper()
	out := snap
	items := make([]any, 0, len(records))
	for _, rec := range records {
		items = append(items, rec)
	}
	for i, ev := range out.EvidenceBundles {
		if ev.TargetID != "target-firmware-system" {
			continue
		}
		var env map[string]any
		if err := json.Unmarshal(ev.Facts, &env); err != nil {
			t.Fatal(err)
		}
		payload := env["payload"].(map[string]any)
		payload["drive_health"] = items
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		out.EvidenceBundles[i].Facts = raw
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return out
}

func topologyWithoutBDCCandidates(t *testing.T, fix resolvedFixture) domain.WindowsBootTopology {
	t.Helper()
	topo := fix.Topology
	filtered := make([]domain.TopologyCandidate, 0, len(topo.Candidates))
	for _, c := range topo.Candidates {
		if c.Role == domain.RoleBCDStore {
			continue
		}
		filtered = append(filtered, c)
	}
	topo.Candidates = filtered
	topo.Selection.BCDTargetID = ""
	topo.MutationEligibility.Eligible = false
	seen := map[string]struct{}{}
	blockers := make([]string, 0, len(topo.MutationEligibility.Blockers)+1)
	for _, b := range topo.MutationEligibility.Blockers {
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		blockers = append(blockers, b)
	}
	if _, ok := seen["bcd_missing"]; !ok {
		blockers = append(blockers, "bcd_missing")
	}
	topo.MutationEligibility.Blockers = blockers
	if err := topo.Validate(); err != nil {
		t.Fatalf("topology invalid: %v", err)
	}
	return topo
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
		EvidenceID: evidenceID, CaseID: testCaseID, TargetID: targetID,
		Collector: "legacy", CollectorVersion: "1.0.0", CapturedAt: "2026-07-27T12:00:00Z",
		SourceStatus: "ok", FactsSchema: legacyreport.FactsSchemaID, Facts: raw,
		Artifacts: []domain.ArtifactRef{}, Limitations: []string{},
	}
}

func filterStrings(in []string, drop ...string) []string {
	dropSet := make(map[string]struct{}, len(drop))
	for _, d := range drop {
		dropSet[d] = struct{}{}
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, skip := dropSet[v]; skip {
			continue
		}
		out = append(out, v)
	}
	return out
}

func filterTargets(in []domain.Target, drop ...string) []domain.Target {
	dropSet := make(map[string]struct{}, len(drop))
	for _, d := range drop {
		dropSet[d] = struct{}{}
	}
	out := make([]domain.Target, 0, len(in))
	for _, tg := range in {
		if _, skip := dropSet[tg.TargetID]; skip {
			continue
		}
		out = append(out, tg)
	}
	return out
}

func filterEvidence(in []domain.EvidenceBundle, dropTargetOrID ...string) []domain.EvidenceBundle {
	dropSet := make(map[string]struct{}, len(dropTargetOrID))
	for _, d := range dropTargetOrID {
		dropSet[d] = struct{}{}
	}
	out := make([]domain.EvidenceBundle, 0, len(in))
	for _, ev := range in {
		if _, skip := dropSet[ev.TargetID]; skip {
			continue
		}
		if _, skip := dropSet[ev.EvidenceID]; skip {
			continue
		}
		out = append(out, ev)
	}
	return out
}
