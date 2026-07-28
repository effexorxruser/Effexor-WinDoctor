package legacyreport_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestImportDoesNotRequireFactsSchemaFile(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	schemaPath := filepath.Clean(filepath.Join(
		filepath.Dir(file),
		"..", "..", "..", "..",
		"contracts", "recovery", "facts",
		"legacy-diagnostic-report-fragment-1.0.0",
		"legacy-diagnostic-report-fragment.schema.json",
	))
	hiddenPath := schemaPath + ".hidden-for-test"
	if err := os.Rename(schemaPath, hiddenPath); err != nil {
		t.Fatalf("hide schema: %v", err)
	}
	defer func() {
		if err := os.Rename(hiddenPath, schemaPath); err != nil {
			t.Errorf("restore schema: %v", err)
		}
	}()

	if _, err := os.Stat(schemaPath); !os.IsNotExist(err) {
		t.Fatalf("schema file still visible: %v", err)
	}
	if _, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{}); err != nil {
		t.Fatalf("ImportJSON must not depend on schema file: %v", err)
	}
}

func TestDuplicateDiskNumberOmitsPartitionRelation(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-duplicate-disk-number.json")
	result, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "matches") && strings.Contains(w, "disk targets") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("expected duplicate disk warning, got %#v", result.Warnings)
	}
	for _, bundle := range result.EvidenceBundles {
		var facts map[string]any
		_ = json.Unmarshal(bundle.Facts, &facts)
		if facts["entity_kind"] != "partition" {
			continue
		}
		if len(toStringSlice(facts["related_target_ids"])) != 0 {
			t.Fatal("partition→disk relation must be omitted when disk numbers are ambiguous")
		}
	}
}

func TestInvalidLocatorsOmittedWithLimitation(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	installs := report["windows_installations"].([]any)
	inst := installs[0].(map[string]any)
	inst["root"] = "   "
	inst["system_hive"] = "\u0000"
	inst["software_hive"] = ""
	boot := report["boot"].(map[string]any)
	stores := boot["bcd_stores"].([]any)
	store := stores[0].(map[string]any)
	store["path"] = "\u0000"
	mutated, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result, err := legacyreport.ImportJSON(mutated, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range result.Targets {
		switch target.TargetType {
		case "windows_installation":
			if _, ok := target.RuntimeLocators["root"]; ok {
				t.Fatal("whitespace root must not be a locator")
			}
			if _, ok := target.RuntimeLocators["system_hive"]; ok {
				t.Fatal("NUL system_hive must not be a locator")
			}
			if _, ok := target.RuntimeLocators["software_hive"]; ok {
				t.Fatal("empty software_hive must not be a locator")
			}
			if !hasOmittedLocatorLimitation(target.Limitations, "root") {
				t.Fatalf("missing root omission limitation: %#v", target.Limitations)
			}
		case "boot_store":
			if target.RuntimeLocators["path"] == "\u0000" {
				t.Fatal("NUL BCD path must not be retained")
			}
			if path, ok := target.RuntimeLocators["path"]; ok && strings.ContainsRune(path, 0) {
				t.Fatal("NUL retained in path locator")
			}
		case "partition":
			if letter, ok := target.RuntimeLocators["drive_letter"]; ok {
				if letter == "" || strings.ContainsRune(letter, 0) {
					t.Fatalf("invalid drive_letter retained: %q", letter)
				}
			}
		}
	}
}

func TestSourceArtifactHashMismatchRejected(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	artifact := validSourceArtifact(raw)
	artifact.SHA256 = strings.Repeat("a", 64)
	_, err := legacyreport.ImportJSON(raw, legacyreport.Options{SourceArtifact: &artifact})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
}

func TestSourceArtifactSizeMismatchRejected(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	artifact := validSourceArtifact(raw)
	artifact.SizeBytes = int64(len(raw)) + 1
	_, err := legacyreport.ImportJSON(raw, legacyreport.Options{SourceArtifact: &artifact})
	if err == nil || !strings.Contains(err.Error(), "size_bytes") {
		t.Fatalf("expected size mismatch, got %v", err)
	}
}

func TestValidateTamperingRules(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-bitlocker-partial.json")
	base, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(r *legacyreport.Result)
	}{
		{"facts_schema", func(r *legacyreport.Result) {
			r.EvidenceBundles[0].FactsSchema = "wrong"
		}},
		{"source_path_vs_identity", func(r *legacyreport.Result) {
			r.Targets[0].StableIdentity["legacy_source_path"] = "tampered-path"
		}},
		{"normalized_hash_vs_identity", func(r *legacyreport.Result) {
			r.Targets[0].StableIdentity["legacy_report_hash"] = strings.Repeat("b", 64)
		}},
		{"inconsistent_report_id", func(r *legacyreport.Result) {
			var facts map[string]any
			_ = json.Unmarshal(r.EvidenceBundles[1].Facts, &facts)
			facts["source_report_id"] = "tampered-report-id"
			r.EvidenceBundles[1].Facts, _ = json.Marshal(facts)
		}},
		{"inconsistent_raw_hash", func(r *legacyreport.Result) {
			var facts map[string]any
			_ = json.Unmarshal(r.EvidenceBundles[1].Facts, &facts)
			facts["raw_source_sha256"] = strings.Repeat("c", 64)
			r.EvidenceBundles[1].Facts, _ = json.Marshal(facts)
		}},
		{"inconsistent_normalized_hash", func(r *legacyreport.Result) {
			var facts map[string]any
			_ = json.Unmarshal(r.EvidenceBundles[1].Facts, &facts)
			facts["normalized_report_sha256"] = strings.Repeat("d", 64)
			// keep identity match for this bundle's target so hash-vs-identity
			// is not the first failure; consistency across bundles should fail.
			r.Targets[1].StableIdentity["legacy_report_hash"] = strings.Repeat("d", 64)
			r.EvidenceBundles[1].Facts, _ = json.Marshal(facts)
		}},
		{"inconsistent_source_collector", func(r *legacyreport.Result) {
			var facts map[string]any
			_ = json.Unmarshal(r.EvidenceBundles[1].Facts, &facts)
			facts["source_collector"] = "tampered-collector"
			r.EvidenceBundles[1].Facts, _ = json.Marshal(facts)
		}},
		{"bundle_collector", func(r *legacyreport.Result) {
			r.EvidenceBundles[0].Collector = "tampered"
		}},
		{"bundle_collector_version", func(r *legacyreport.Result) {
			r.EvidenceBundles[0].CollectorVersion = "9.9.9"
		}},
		{"captured_at", func(r *legacyreport.Result) {
			r.EvidenceBundles[0].CapturedAt = "2020-01-01T00:00:00Z"
		}},
		{"broken_related_ref", func(r *legacyreport.Result) {
			var facts map[string]any
			_ = json.Unmarshal(r.EvidenceBundles[0].Facts, &facts)
			facts["related_target_ids"] = []string{"target-does-not-exist-xxxxxxxx"}
			r.EvidenceBundles[0].Facts, _ = json.Marshal(facts)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clone := cloneResult(t, base)
			test.mutate(&clone)
			if err := clone.Validate(); err == nil {
				t.Fatal("expected Validate rejection")
			}
		})
	}
}

func validSourceArtifact(raw []byte) domain.ArtifactRef {
	sum := sha256.Sum256(raw)
	return domain.ArtifactRef{
		ArtifactID:          "artifact-aaaaaaaaaaaaaaaaaaaaaaaa",
		Kind:                "report",
		RelativePath:        "imports/report.json",
		SHA256:              hex.EncodeToString(sum[:]),
		SizeBytes:           int64(len(raw)),
		CreatedAt:           "2026-07-27T14:00:00Z",
		MediaClassification: "case_local",
	}
}

func hasOmittedLocatorLimitation(lims []string, key string) bool {
	for _, lim := range lims {
		if strings.Contains(lim, "runtime locator") && strings.Contains(lim, key) && strings.Contains(lim, "omitted") {
			return true
		}
	}
	return false
}

func cloneResult(t *testing.T, in legacyreport.Result) legacyreport.Result {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out legacyreport.Result
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
