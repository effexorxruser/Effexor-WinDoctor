package evidenceview_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/evidenceview"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestDecodeLegacyFirmwareBundle(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"boot_firmware_mode": "uefi",
		"hardware":           map[string]any{"firmware_mode": "uefi"},
		"drive_health":       []any{},
	}
	env := map[string]any{
		"schema_name":              "legacy-diagnostic-report-fragment",
		"schema_version":           "1.0.0",
		"source_schema_name":       "diagnostic-report",
		"source_schema_version":    "1.3.0",
		"source_report_id":         "report000000000001",
		"raw_source_sha256":        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"normalized_report_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"source_collector":         "effexorwinpe-collector",
		"source_collector_version": "0.1.0",
		"source_path":              "firmware",
		"entity_kind":              "firmware_environment",
		"payload":                  payload,
		"related_target_ids":       []string{},
		"limitations":              []string{"drive_letters_runtime_only"},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	bundle := domain.EvidenceBundle{
		SchemaName: domain.SchemaEvidenceBundle, SchemaVersion: domain.SchemaVersion,
		EvidenceID: "evidence-bbbbbbbbbbbbbbbbbbbbbbbb", CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		TargetID: "target-firmware-system", Collector: "legacy", CollectorVersion: "1.0.0",
		CapturedAt: "2026-07-27T12:00:00Z", SourceStatus: "ok",
		FactsSchema: legacyreport.FactsSchemaID, Facts: raw,
		Artifacts: []domain.ArtifactRef{}, Limitations: []string{},
	}
	view, err := evidenceview.DecodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := view.Firmware()
	if err != nil {
		t.Fatal(err)
	}
	if fw.BootFirmwareMode != "uefi" {
		t.Fatalf("firmware mode %q", fw.BootFirmwareMode)
	}
}

func TestUnsupportedSchema(t *testing.T) {
	t.Parallel()
	bundle := domain.EvidenceBundle{
		FactsSchema: "unknown-schema",
		Facts:       []byte(`{}`),
	}
	_, err := evidenceview.DecodeBundle(bundle)
	if !errors.Is(err, evidenceview.ErrUnsupportedSchema) {
		t.Fatalf("want ErrUnsupportedSchema, got %v", err)
	}
}

func TestDiskPayloadUsesDiagnosticReportNumberField(t *testing.T) {
	t.Parallel()
	bundle := legacyBundle(t, "evidence-cccccccccccccccccccccccc", "target-disk-nvme0n1", "disk", map[string]any{
		"number": json.Number("0"), "partition_style": "GPT",
	}, nil)
	view, err := evidenceview.DecodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := view.Disk()
	if err != nil {
		t.Fatal(err)
	}
	if disk.DiskNumber == nil || *disk.DiskNumber != 0 {
		t.Fatalf("disk number = %v", disk.DiskNumber)
	}
}

func TestWindowsInstallationPayloadUsesRootAndVersionObject(t *testing.T) {
	t.Parallel()
	bundle := legacyBundle(t, "evidence-ffffffffffffffffffffffff", "target-windows-install-01", "windows_installation", map[string]any{
		"root": `C:\Windows`, "version": map[string]any{"product_name": "Windows 10", "build": "19045"},
	}, nil)
	view, err := evidenceview.DecodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	win, err := view.WindowsInstallation()
	if err != nil {
		t.Fatal(err)
	}
	if win.RootPath != `C:\Windows` {
		t.Fatalf("root = %q", win.RootPath)
	}
	if win.Version != "Windows 10" {
		t.Fatalf("version = %q", win.Version)
	}
}

func TestDecodeBundleRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	bundle := legacyBundle(t, "evidence-cccccccccccccccccccccccc", "target-disk-nvme0n1", "disk", map[string]any{
		"number": json.Number("0"),
	}, nil)
	bundle.Facts = append(bundle.Facts, []byte("{}")...)
	_, err := evidenceview.DecodeBundle(bundle)
	if !errors.Is(err, evidenceview.ErrMalformedEvidence) {
		t.Fatalf("want ErrMalformedEvidence, got %v", err)
	}
}

func TestDiskRejectsTrailingJSONPayload(t *testing.T) {
	t.Parallel()
	bundle := legacyBundle(t, "evidence-cccccccccccccccccccccccc", "target-disk-nvme0n1", "disk", map[string]any{
		"number": json.Number("0"), "partition_style": "GPT",
	}, nil)
	view, err := evidenceview.DecodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	view.Envelope.Payload = json.RawMessage(`{"number":0}{}`)
	_, err = view.Disk()
	if !errors.Is(err, evidenceview.ErrMalformedEvidence) {
		t.Fatalf("want ErrMalformedEvidence, got %v", err)
	}
}

func TestWindowsInstallationRejectsTrailingJSONPayload(t *testing.T) {
	t.Parallel()
	bundle := legacyBundle(t, "evidence-ffffffffffffffffffffffff", "target-windows-install-01", "windows_installation", map[string]any{
		"root": `C:\Windows`, "version": map[string]any{"product_name": "Windows 10", "build": "19045"},
	}, nil)
	view, err := evidenceview.DecodeBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	view.Envelope.Payload = json.RawMessage(`{"root":"C:\\Windows"}{}`)
	_, err = view.WindowsInstallation()
	if !errors.Is(err, evidenceview.ErrMalformedEvidence) {
		t.Fatalf("want ErrMalformedEvidence, got %v", err)
	}
}

func legacyBundle(t *testing.T, evidenceID, targetID, kind string, payload map[string]any, related []string) domain.EvidenceBundle {
	t.Helper()
	if related == nil {
		related = []string{}
	}
	env := map[string]any{
		"schema_name":              "legacy-diagnostic-report-fragment",
		"schema_version":           "1.0.0",
		"source_schema_name":       "diagnostic-report",
		"source_schema_version":    "1.3.0",
		"source_report_id":         "report000000000001",
		"raw_source_sha256":        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"normalized_report_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"source_collector":         "effexorwinpe-collector",
		"source_collector_version": "0.1.0",
		"source_path":              kind,
		"entity_kind":              kind,
		"payload":                  payload,
		"related_target_ids":       related,
		"limitations":              []string{},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return domain.EvidenceBundle{
		SchemaName: domain.SchemaEvidenceBundle, SchemaVersion: domain.SchemaVersion,
		EvidenceID: evidenceID, CaseID: "case-aaaaaaaaaaaaaaaaaaaaaaaa",
		TargetID: targetID, Collector: "legacy", CollectorVersion: "1.0.0",
		CapturedAt: "2026-07-27T12:00:00Z", SourceStatus: "ok",
		FactsSchema: legacyreport.FactsSchemaID, Facts: raw,
		Artifacts: []domain.ArtifactRef{}, Limitations: []string{},
	}
}
