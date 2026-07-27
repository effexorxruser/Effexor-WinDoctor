package validation_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/diagnostics"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/validation"
)

func fixturesRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "recovery"))
}

func TestCompileAllRecoverySchemas(t *testing.T) {
	t.Parallel()
	schemas, err := validation.CompileAll()
	if err != nil {
		t.Fatalf("CompileAll() error = %v", err)
	}
	want := []string{
		"common",
		domain.SchemaCaseManifest,
		domain.SchemaTarget,
		domain.SchemaEvidenceBundle,
		domain.SchemaFinding,
		domain.SchemaRepairPlan,
		domain.SchemaOperationDescriptor,
		domain.SchemaExecutionEvent,
		domain.SchemaVerificationReport,
	}
	for _, name := range want {
		if schemas[name] == nil {
			t.Fatalf("missing compiled schema %q", name)
		}
	}
}

func TestSchemaAcceptsValidFixtures(t *testing.T) {
	t.Parallel()
	mapping := map[string]string{
		"case-manifest.json":        domain.SchemaCaseManifest,
		"target.json":               domain.SchemaTarget,
		"evidence-bundle.json":      domain.SchemaEvidenceBundle,
		"finding.json":              domain.SchemaFinding,
		"finding-insufficient.json": domain.SchemaFinding,
		"repair-plan.json":          domain.SchemaRepairPlan,
		"operation-descriptor.json": domain.SchemaOperationDescriptor,
		"execution-event.json":      domain.SchemaExecutionEvent,
		"verification-report.json":  domain.SchemaVerificationReport,
	}
	for file, schemaName := range mapping {
		file, schemaName := file, schemaName
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(fixturesRoot(t), "valid", file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if err := validation.ValidateJSON(schemaName, raw); err != nil {
				t.Fatalf("ValidateJSON() error = %v", err)
			}
		})
	}
}

func TestSchemaRejectsInvalidFixtures(t *testing.T) {
	t.Parallel()
	mapping := map[string]string{
		"case-manifest-bad-enum.json":        domain.SchemaCaseManifest,
		"case-manifest-bad-timestamp.json":   domain.SchemaCaseManifest,
		"case-manifest-unknown-field.json":   domain.SchemaCaseManifest,
		"target-unknown-field.json":          domain.SchemaTarget,
		"evidence-unsafe-relative-path.json": domain.SchemaEvidenceBundle,
		"evidence-bad-sha256.json":           domain.SchemaEvidenceBundle,
		"operation-raw-command.json":         domain.SchemaOperationDescriptor,
		"execution-bad-enum.json":            domain.SchemaExecutionEvent,
		"verification-bad-evidence-ref.json": domain.SchemaVerificationReport,
	}
	for file, schemaName := range mapping {
		file, schemaName := file, schemaName
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(fixturesRoot(t), "invalid", file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if err := validation.ValidateJSON(schemaName, raw); err == nil {
				t.Fatal("expected schema rejection")
			}
		})
	}
}

func TestLegacyDiagnosticReportUnchanged(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "contracts", "diagnostic-report.schema.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read diagnostic-report schema: %v", err)
	}
	if !strings.Contains(string(raw), `"const": "1.3.0"`) ||
		!strings.Contains(string(raw), `"$id": "https://effexorwinpe.local/contracts/diagnostic-report.schema.json"`) {
		t.Fatal("diagnostic-report 1.3.0 contract appears altered")
	}

	minimal := []byte(`{
		"schema_version":"1.3.0",
		"report_id":"report000000000001",
		"collected_at":"2026-07-22T12:00:00Z",
		"collector":{"name":"effexorwinpe-collector","version":"test"},
		"environment":{"runtime_os":"windows","runtime_arch":"amd64"},
		"hardware":{"firmware_mode":"uefi","system":{},"processor":{"cores":0,"logical_processors":0},"memory":{"total_physical_bytes":0},"network_adapters":[]},
		"storage":{"disks":[],"drive_health":[],"partitions":[],"bitlocker_volumes":[],"bitlocker_inventory":{"status":"ok"}},
		"boot":{"firmware_mode":"uefi","bcd_stores":[]},
		"windows_installations":[],
		"checks":[],
		"privacy":{"contains_personal_data":false,"excluded_by_default":[]}
	}`)
	if _, err := diagnostics.DecodeReportJSON(minimal); err != nil {
		t.Fatalf("DecodeReportJSON() error = %v", err)
	}
}
