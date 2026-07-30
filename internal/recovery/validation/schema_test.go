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
		domain.SchemaCaseWorkflowState,
		domain.SchemaCoordinatorEvent,
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
		"case-manifest.json":            domain.SchemaCaseManifest,
		"target.json":                   domain.SchemaTarget,
		"evidence-bundle.json":          domain.SchemaEvidenceBundle,
		"finding.json":                  domain.SchemaFinding,
		"finding-insufficient.json":     domain.SchemaFinding,
		"repair-plan.json":              domain.SchemaRepairPlan,
		"repair-plan-ordered-deps.json": domain.SchemaRepairPlan,
		"operation-descriptor.json":     domain.SchemaOperationDescriptor,
		"execution-event.json":          domain.SchemaExecutionEvent,
		"execution-event-started.json":  domain.SchemaExecutionEvent,
		"execution-event-failed.json":   domain.SchemaExecutionEvent,
		"verification-report.json":      domain.SchemaVerificationReport,
		"case-workflow-state.json":      domain.SchemaCaseWorkflowState,
		"coordinator-event.json":        domain.SchemaCoordinatorEvent,
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
		"case-manifest-bad-enum.json":                    domain.SchemaCaseManifest,
		"case-manifest-bad-timestamp.json":               domain.SchemaCaseManifest,
		"case-manifest-unknown-field.json":               domain.SchemaCaseManifest,
		"target-unknown-field.json":                      domain.SchemaTarget,
		"evidence-unsafe-relative-path.json":             domain.SchemaEvidenceBundle,
		"evidence-bad-sha256.json":                       domain.SchemaEvidenceBundle,
		"finding-missing-evidence.json":                  domain.SchemaFinding,
		"operation-raw-command.json":                     domain.SchemaOperationDescriptor,
		"operation-readonly-mutation.json":               domain.SchemaOperationDescriptor,
		"operation-readonly-backup.json":                 domain.SchemaOperationDescriptor,
		"operation-nonreadonly-mutation-none.json":       domain.SchemaOperationDescriptor,
		"operation-controlled-no-approval.json":          domain.SchemaOperationDescriptor,
		"operation-destructive-no-approval.json":         domain.SchemaOperationDescriptor,
		"operation-irreversible-no-approval.json":        domain.SchemaOperationDescriptor,
		"operation-irreversible-rollback.json":           domain.SchemaOperationDescriptor,
		"operation-reversible-unavailable-rollback.json": domain.SchemaOperationDescriptor,
		"execution-bad-enum.json":                        domain.SchemaExecutionEvent,
		"execution-started-with-completed-at.json":       domain.SchemaExecutionEvent,
		"execution-started-with-exit-code.json":          domain.SchemaExecutionEvent,
		"execution-terminal-missing-completed-at.json":   domain.SchemaExecutionEvent,
		"execution-succeeded-with-error.json":            domain.SchemaExecutionEvent,
		"execution-failed-missing-error.json":            domain.SchemaExecutionEvent,
		"verification-bad-evidence-ref.json":             domain.SchemaVerificationReport,
		"case-workflow-state-bad-enum.json":              domain.SchemaCaseWorkflowState,
		"case-workflow-state-unknown-field.json":         domain.SchemaCaseWorkflowState,
		"case-workflow-state-bad-id.json":                domain.SchemaCaseWorkflowState,
		"case-workflow-state-bad-timestamp.json":         domain.SchemaCaseWorkflowState,
		"case-workflow-state-missing-transition.json":    domain.SchemaCaseWorkflowState,
		"case-workflow-state-bad-failure.json":           domain.SchemaCaseWorkflowState,
		"coordinator-event-bad-enum.json":                domain.SchemaCoordinatorEvent,
		"coordinator-event-bad-actor.json":               domain.SchemaCoordinatorEvent,
		"coordinator-event-bad-id.json":                  domain.SchemaCoordinatorEvent,
		"coordinator-event-bad-timestamp.json":           domain.SchemaCoordinatorEvent,
		"coordinator-event-bad-reason.json":              domain.SchemaCoordinatorEvent,
		"coordinator-event-missing-refs.json":            domain.SchemaCoordinatorEvent,
		"coordinator-event-unknown-field.json":           domain.SchemaCoordinatorEvent,
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

// goOnlyDependencyGraphFixtures are accepted by JSON Schema (single-document)
// but rejected by Go RepairPlan dependency-graph validation.
var goOnlyDependencyGraphFixtures = map[string]struct{}{
	"repair-plan-bad-dependency.json":       {},
	"repair-plan-self-dependency.json":      {},
	"repair-plan-forward-dependency.json":   {},
	"repair-plan-duplicate-dependency.json": {},
	"repair-plan-cycle.json":                {},
}

func goValidateFixture(schemaName, file string, raw []byte) error {
	switch schemaName {
	case domain.SchemaCaseManifest:
		var v domain.CaseManifest
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaTarget:
		var v domain.Target
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaEvidenceBundle:
		var v domain.EvidenceBundle
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaFinding:
		var v domain.Finding
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaRepairPlan:
		var v domain.RepairPlan
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaOperationDescriptor:
		_, err := domain.DecodeOperationDescriptorStrict(raw)
		return err
	case domain.SchemaExecutionEvent:
		var v domain.ExecutionEvent
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaVerificationReport:
		var v domain.VerificationReport
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaCaseWorkflowState:
		var v domain.CaseWorkflowState
		return domain.DecodeAndValidateJSON(raw, &v)
	case domain.SchemaCoordinatorEvent:
		var v domain.CoordinatorEvent
		if err := domain.DecodeAndValidateJSON(raw, &v); err != nil {
			return err
		}
		return domain.ValidatePR17CoordinatorEventSemantics(v)
	default:
		return nil
	}
}

func TestSchemaGoParity(t *testing.T) {
	t.Parallel()

	validMapping := map[string]string{
		"case-manifest.json":            domain.SchemaCaseManifest,
		"target.json":                   domain.SchemaTarget,
		"evidence-bundle.json":          domain.SchemaEvidenceBundle,
		"finding.json":                  domain.SchemaFinding,
		"finding-insufficient.json":     domain.SchemaFinding,
		"repair-plan.json":              domain.SchemaRepairPlan,
		"repair-plan-ordered-deps.json": domain.SchemaRepairPlan,
		"operation-descriptor.json":     domain.SchemaOperationDescriptor,
		"execution-event.json":          domain.SchemaExecutionEvent,
		"execution-event-started.json":  domain.SchemaExecutionEvent,
		"execution-event-failed.json":   domain.SchemaExecutionEvent,
		"verification-report.json":      domain.SchemaVerificationReport,
		"case-workflow-state.json":      domain.SchemaCaseWorkflowState,
		"coordinator-event.json":        domain.SchemaCoordinatorEvent,
	}
	for file, schemaName := range validMapping {
		file, schemaName := file, schemaName
		t.Run("valid/"+file, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(fixturesRoot(t), "valid", file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			schemaErr := validation.ValidateJSON(schemaName, raw)
			goErr := goValidateFixture(schemaName, file, raw)
			if schemaErr != nil {
				t.Fatalf("schema reject valid fixture: %v", schemaErr)
			}
			if goErr != nil {
				t.Fatalf("go reject valid fixture: %v", goErr)
			}
		})
	}

	invalidDir := filepath.Join(fixturesRoot(t), "invalid")
	entries, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatalf("readdir invalid: %v", err)
	}
	schemaByPrefix := []struct {
		prefix string
		schema string
	}{
		{"case-manifest-", domain.SchemaCaseManifest},
		{"case-workflow-state-", domain.SchemaCaseWorkflowState},
		{"coordinator-event-", domain.SchemaCoordinatorEvent},
		{"target-", domain.SchemaTarget},
		{"evidence-", domain.SchemaEvidenceBundle},
		{"finding-", domain.SchemaFinding},
		{"repair-plan-", domain.SchemaRepairPlan},
		{"operation-", domain.SchemaOperationDescriptor},
		{"execution-", domain.SchemaExecutionEvent},
		{"verification-", domain.SchemaVerificationReport},
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		file := entry.Name()
		var schemaName string
		for _, rule := range schemaByPrefix {
			if strings.HasPrefix(file, rule.prefix) {
				schemaName = rule.schema
				break
			}
		}
		if schemaName == "" {
			t.Fatalf("no schema mapping for invalid fixture %s", file)
		}
		fileName, mappedSchema := file, schemaName
		t.Run("invalid/"+fileName, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join(invalidDir, fileName))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			schemaErr := validation.ValidateJSON(mappedSchema, raw)
			goErr := goValidateFixture(mappedSchema, fileName, raw)
			_, goOnly := goOnlyDependencyGraphFixtures[fileName]
			if goOnly {
				if goErr == nil {
					t.Fatal("expected Go rejection for dependency-graph fixture")
				}
				if schemaErr != nil {
					t.Fatalf("Go-only dependency fixture unexpectedly rejected by schema: %v", schemaErr)
				}
				return
			}
			if schemaErr == nil {
				t.Fatal("expected schema rejection")
			}
			if goErr == nil {
				t.Fatal("expected Go rejection")
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
