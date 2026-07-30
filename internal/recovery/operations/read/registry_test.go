package read

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestNewRegistryRegistersEightOperations(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	descs := reg.Descriptors()
	if len(descs) != 8 {
		t.Fatalf("descriptors = %d, want 8", len(descs))
	}
	want := []string{
		"windows.inspect_installation",
		"boot.inspect_firmware_mode",
		"boot.inspect_bcd_store",
		"boot.inspect_efi_layout",
		"storage.inspect_disk_health",
		"storage.inspect_partition_layout",
		"bitlocker.inspect_inventory",
		"case.verify_store_integrity",
	}
	for _, id := range want {
		desc, ok := reg.Descriptor(id, "1.0.0")
		if !ok {
			t.Fatalf("missing descriptor %q", id)
		}
		if desc.RiskClass != domain.RiskReadOnly || desc.MutationClass != "none" || desc.RequiresBackup || desc.RequiresExplicitApproval {
			t.Fatalf("descriptor %q safety mismatch", id)
		}
	}
}

func TestExecuteInspectFirmwareMode(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	snap := testSnapshot(t)
	req := Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-111111111111111111111111", CaseID: snap.Case.CaseID,
			OperationID: "boot.inspect_firmware_mode", OperationVersion: "1.0.0",
			TargetID: "target-firmware-system", Parameters: json.RawMessage(`{}`),
		},
		Snapshot: snap,
	}
	res, err := reg.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != domain.ReadStatusOK {
		t.Fatalf("status = %q", res.Status)
	}
	if res.ObservationSource != domain.ObservationCaseSnapshot {
		t.Fatalf("source = %q", res.ObservationSource)
	}
	var facts map[string]any
	if err := json.Unmarshal(res.Facts, &facts); err != nil {
		t.Fatal(err)
	}
	if facts["firmware_mode"] != "uefi" {
		t.Fatalf("firmware_mode = %v", facts["firmware_mode"])
	}
}

func TestExecuteRejectsUnknownOperation(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Execute(context.Background(), Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-222222222222222222222222", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			OperationID: "unknown.op", OperationVersion: "1.0.0",
			TargetID: "target-firmware-system", Parameters: json.RawMessage(`{}`),
		},
		Snapshot: testSnapshot(t),
	})
	if !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("err = %v", err)
	}
}

func TestExecuteRejectsWrongTargetType(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Execute(context.Background(), Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-333333333333333333333333", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			OperationID: "boot.inspect_firmware_mode", OperationVersion: "1.0.0",
			TargetID: "target-disk-nvme0n1", Parameters: json.RawMessage(`{}`),
		},
		Snapshot: testSnapshot(t),
	})
	if !errors.Is(err, ErrUnsupportedTargetType) {
		t.Fatalf("err = %v", err)
	}
}

func TestExecuteRejectsCancelledContext(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = reg.Execute(ctx, Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-444444444444444444444444", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			OperationID: "boot.inspect_firmware_mode", OperationVersion: "1.0.0",
			TargetID: "target-firmware-system", Parameters: json.RawMessage(`{}`),
		},
		Snapshot: testSnapshot(t),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyStoreIntegrityUsesVerifier(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry(WithStoreVerifier(fakeVerifier{
		report: casestore.IntegrityReport{
			CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa", CheckedAt: "2026-07-27T12:20:00Z",
			Status: casestore.IntegrityOK, StagingEntries: []string{}, OrphanSnapshots: []string{},
			OrphanArtifacts: []string{}, TemporaryFiles: []string{}, Warnings: []string{}, Errors: []string{},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := reg.Execute(context.Background(), Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-555555555555555555555555", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			OperationID: "case.verify_store_integrity", OperationVersion: "1.0.0",
			TargetID: "target-firmware-system", Parameters: json.RawMessage(`{}`),
		},
		Snapshot: testSnapshot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ObservationSource != domain.ObservationCaseStore {
		t.Fatalf("source = %q", res.ObservationSource)
	}
}

func TestVerifyStoreIntegrityRequiresVerifier(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Execute(context.Background(), Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-666666666666666666666666", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			OperationID: "case.verify_store_integrity", OperationVersion: "1.0.0",
			TargetID: "target-firmware-system", Parameters: json.RawMessage(`{}`),
		},
		Snapshot: testSnapshot(t),
	})
	if !errors.Is(err, ErrMissingStoreVerifier) {
		t.Fatalf("err = %v", err)
	}
}

func TestEvidenceFromResultDeterministic(t *testing.T) {
	t.Parallel()
	result := domain.ReadOperationResult{
		SchemaName: domain.SchemaReadOperationResult, SchemaVersion: domain.SchemaVersion,
		RequestID: "readreq-111111111111111111111111", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		OperationID: "boot.inspect_firmware_mode", OperationVersion: "1.0.0",
		TargetID: "target-firmware-system", ObservedAt: "2026-07-27T12:10:00Z",
		Status: domain.ReadStatusOK, ObservationSource: domain.ObservationCaseSnapshot,
		SourceEvidenceIDs: []string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
		Facts:             json.RawMessage(`{"firmware_mode":"uefi"}`),
		Limitations:       []string{},
	}
	a, err := EvidenceFromResult(result, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EvidenceFromResult(result, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if a.EvidenceID != b.EvidenceID {
		t.Fatalf("nondeterministic evidence id: %s vs %s", a.EvidenceID, b.EvidenceID)
	}
	shifted := result
	shifted.ObservedAt = "2026-07-27T13:00:00Z"
	c, err := EvidenceFromResult(shifted, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if a.EvidenceID != c.EvidenceID {
		t.Fatalf("observed_at affected evidence id")
	}
}

func TestDescriptorsDefensiveCopy(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	descs := reg.Descriptors()
	if len(descs) == 0 || len(descs[0].RequiredEvidence) == 0 {
		t.Fatal("expected descriptors with required_evidence")
	}
	original := descs[0].RequiredEvidence[0]
	descs[0].RequiredEvidence[0] = "mutated"
	desc, _ := reg.Descriptor(descs[0].OperationID, descs[0].Version)
	if desc.RequiredEvidence[0] != original {
		t.Fatalf("RequiredEvidence copy was not defensive: got %q want %q", desc.RequiredEvidence[0], original)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mut := reg.Descriptors()
			if len(mut) != 8 {
				t.Errorf("descriptors = %d", len(mut))
			}
			if len(mut[0].RequiredEvidence) > 0 {
				mut[0].RequiredEvidence[0] = "mutated"
			}
		}()
	}
	wg.Wait()
	desc, _ = reg.Descriptor("windows.inspect_installation", "1.0.0")
	if len(desc.RequiredEvidence) > 0 && desc.RequiredEvidence[0] == "mutated" {
		t.Fatal("concurrent RequiredEvidence mutation leaked into registry")
	}
}

func TestExecuteRejectsTrailingJSONParameters(t *testing.T) {
	t.Parallel()
	reg, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Execute(context.Background(), Request{
		ReadOperationRequest: domain.ReadOperationRequest{
			SchemaName: domain.SchemaReadOperationRequest, SchemaVersion: domain.SchemaVersion,
			RequestID: "readreq-777777777777777777777777", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			OperationID: "boot.inspect_firmware_mode", OperationVersion: "1.0.0",
			TargetID: "target-firmware-system", Parameters: json.RawMessage(`{}{}`),
		},
		Snapshot: testSnapshot(t),
	})
	if !errors.Is(err, ErrMalformedParameters) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateCatalogEntryRejections(t *testing.T) {
	t.Parallel()
	base := catalogEntries()[0].descriptor
	cases := []struct {
		name string
		desc domain.OperationDescriptor
	}{
		{
			name: "non_read_only",
			desc: func() domain.OperationDescriptor {
				d := base
				d.RiskClass = domain.RiskDestructive
				d.MutationClass = "data"
				d.RequiresExplicitApproval = true
				return d
			}(),
		},
		{
			name: "requires_backup",
			desc: func() domain.OperationDescriptor {
				d := base
				d.RequiresBackup = true
				return d
			}(),
		},
		{
			name: "missing_schema_ref",
			desc: func() domain.OperationDescriptor {
				d := base
				d.ParametersSchemaRef = ""
				return d
			}(),
		},
		{
			name: "missing_handler",
			desc: base,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var handler handlerFunc
			if tc.name != "missing_handler" {
				handler = func(context.Context, execContext) (domain.ReadOperationResult, error) {
					return domain.ReadOperationResult{}, nil
				}
			}
			if err := validateCatalogEntry(tc.desc, []string{"windows_installation"}, handler); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

type fakeVerifier struct {
	report casestore.IntegrityReport
}

func (f fakeVerifier) Verify(_ context.Context, _ string) (casestore.IntegrityReport, error) {
	return f.report, nil
}

func testSnapshot(t *testing.T) casestore.Snapshot {
	t.Helper()
	firmwareID := "target-firmware-system"
	diskID := "target-disk-nvme0n1"
	partID := "target-part-windows-01"
	espID := "target-part-esp-01"
	winID := "target-windows-install-01"
	bcdID := "target-bcd-store-01"
	snap := casestore.Snapshot{
		Case: domain.CaseManifest{
			SchemaName: domain.SchemaCaseManifest, SchemaVersion: domain.SchemaVersion,
			CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: "2026-07-27T12:00:00Z",
			UpdatedAt: "2026-07-27T12:05:00Z", Runtime: "winpe", CurrentState: domain.CaseStateSnapshotted,
			TargetIDs: []string{firmwareID, diskID, partID, espID, winID, bcdID}, PrivacyClass: "standard",
		},
		Targets: []domain.Target{
			testTarget(firmwareID, "firmware", "Firmware", nil),
			testTarget(diskID, "disk", "Disk 0", map[string]string{"disk_number": "0", "partition_style": "GPT"}),
			testTarget(partID, "partition", "Windows", map[string]string{"disk_number": "0"}),
			testTarget(espID, "partition", "ESP", map[string]string{"disk_number": "0"}),
			testTarget(winID, "windows_installation", "Windows", nil),
			testTarget(bcdID, "boot_store", "BCD", nil),
		},
		EvidenceBundles: []domain.EvidenceBundle{
			testLegacyBundle(t, "evidence-bbbbbbbbbbbbbbbbbbbbbbbb", firmwareID, "firmware_environment", map[string]any{
				"boot_firmware_mode": "uefi", "hardware": map[string]any{"firmware_mode": "uefi"},
				"drive_health": []any{map[string]any{"device_id": "0", "health_status": "Healthy", "operational_status": "OK"}},
			}, nil),
			testLegacyBundle(t, "evidence-cccccccccccccccccccccccc", diskID, "disk", map[string]any{
				"number": json.Number("0"), "partition_style": "GPT",
			}, nil),
			testLegacyBundle(t, "evidence-dddddddddddddddddddddddd", partID, "partition", map[string]any{
				"disk_number": json.Number("0"), "type": "Basic",
			}, []string{diskID}),
			testLegacyBundle(t, "evidence-eeeeeeeeeeeeeeeeeeeeeeee", espID, "partition", map[string]any{
				"disk_number": json.Number("0"), "gpt_type": "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}",
			}, []string{diskID}),
			testLegacyBundle(t, "evidence-ffffffffffffffffffffffff", winID, "windows_installation", map[string]any{
				"root": `C:\Windows`, "version": map[string]any{"product_name": "Windows 10", "build": "19045"},
			}, []string{partID}),
			testLegacyBundle(t, "evidence-111111111111111111111111", bcdID, "boot_store", map[string]any{
				"kind": "system", "path": `\EFI\Microsoft\Boot\BCD`,
			}, []string{espID}),
		},
	}
	if err := snap.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return snap
}

func testTarget(id, typ, name string, loc map[string]string) domain.Target {
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

func testLegacyBundle(t *testing.T, evidenceID, targetID, kind string, payload map[string]any, related []string) domain.EvidenceBundle {
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
