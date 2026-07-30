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
