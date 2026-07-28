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
	withArtifact, err := legacyreport.ImportJSON(raw, legacyreport.Options{
		SourceArtifact: ptrArtifact(validSourceArtifact(raw)),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		base   legacyreport.Result
		mutate func(r *legacyreport.Result)
	}{
		{"facts_schema", base, func(r *legacyreport.Result) {
			r.EvidenceBundles[0].FactsSchema = "wrong"
		}},
		{"source_path_vs_identity", base, func(r *legacyreport.Result) {
			r.Targets[0].StableIdentity["legacy_source_path"] = "tampered-path"
		}},
		{"normalized_hash_vs_identity", base, func(r *legacyreport.Result) {
			r.Targets[0].StableIdentity["legacy_report_hash"] = strings.Repeat("b", 64)
		}},
		{"inconsistent_report_id", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[1], func(facts map[string]any) {
				facts["source_report_id"] = "tampered-report-id"
			})
		}},
		{"inconsistent_raw_hash", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[1], func(facts map[string]any) {
				facts["raw_source_sha256"] = strings.Repeat("c", 64)
			})
		}},
		{"inconsistent_normalized_hash", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[1], func(facts map[string]any) {
				facts["normalized_report_sha256"] = strings.Repeat("d", 64)
			})
			r.Targets[1].StableIdentity["legacy_report_hash"] = strings.Repeat("d", 64)
		}},
		{"inconsistent_source_collector", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[1], func(facts map[string]any) {
				facts["source_collector"] = "tampered-collector"
			})
		}},
		{"bundle_collector", base, func(r *legacyreport.Result) {
			r.EvidenceBundles[0].Collector = "tampered"
		}},
		{"bundle_collector_version", base, func(r *legacyreport.Result) {
			r.EvidenceBundles[0].CollectorVersion = "9.9.9"
		}},
		{"captured_at", base, func(r *legacyreport.Result) {
			r.EvidenceBundles[0].CapturedAt = "2020-01-01T00:00:00Z"
		}},
		{"broken_related_ref", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[0], func(facts map[string]any) {
				facts["related_target_ids"] = []string{"target-does-not-exist-xxxxxxxx"}
			})
		}},
		{"unknown_facts_field", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[0], func(facts map[string]any) {
				facts["unexpected_field"] = true
			})
		}},
		{"payload_null", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[0], func(facts map[string]any) {
				facts["payload"] = nil
			})
		}},
		{"modified_case_id", base, func(r *legacyreport.Result) {
			r.Case.CaseID = "case-ffffffffffffffffffffffff"
			for i := range r.EvidenceBundles {
				r.EvidenceBundles[i].CaseID = r.Case.CaseID
			}
		}},
		{"modified_target_id", base, func(r *legacyreport.Result) {
			r.Targets[1].TargetID = "target-tampered-target-id-01"
			r.Case.TargetIDs[1] = r.Targets[1].TargetID
			r.EvidenceBundles[1].TargetID = r.Targets[1].TargetID
		}},
		{"modified_evidence_id", base, func(r *legacyreport.Result) {
			r.EvidenceBundles[1].EvidenceID = "evidence-ffffffffffffffffffffffff"
		}},
		{"modified_payload_without_fingerprint", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[1], func(facts map[string]any) {
				payload := facts["payload"].(map[string]any)
				payload["friendly_name"] = "tampered-disk-name"
			})
		}},
		{"modified_fingerprint", base, func(r *legacyreport.Result) {
			r.Targets[1].StableIdentity["legacy_entity_fingerprint"] = strings.Repeat("e", 64)
		}},
		{"entity_kind_target_type_mismatch", base, func(r *legacyreport.Result) {
			mutateFacts(t, &r.EvidenceBundles[1], func(facts map[string]any) {
				facts["entity_kind"] = "partition"
			})
		}},
		{"empty_result", base, func(r *legacyreport.Result) {
			r.Targets = nil
			r.EvidenceBundles = nil
			r.Case.TargetIDs = nil
		}},
		{"missing_firmware_target", base, func(r *legacyreport.Result) {
			r.Targets[0].TargetType = "disk"
			mutateFacts(t, &r.EvidenceBundles[0], func(facts map[string]any) {
				facts["entity_kind"] = "disk"
			})
		}},
		{"artifact_only_in_one_bundle", withArtifact, func(r *legacyreport.Result) {
			r.EvidenceBundles[0].Artifacts = []domain.ArtifactRef{}
		}},
		{"divergent_artifacts", withArtifact, func(r *legacyreport.Result) {
			art := r.EvidenceBundles[1].Artifacts[0]
			art.RelativePath = "imports/other.json"
			r.EvidenceBundles[1].Artifacts[0] = art
		}},
		{"divergent_artifacts_same_id", withArtifact, func(r *legacyreport.Result) {
			art := r.EvidenceBundles[1].Artifacts[0]
			art.Kind = "json"
			r.EvidenceBundles[1].Artifacts[0] = art
		}},
		{"artifact_hash_vs_raw_mismatch", withArtifact, func(r *legacyreport.Result) {
			for i := range r.EvidenceBundles {
				art := r.EvidenceBundles[i].Artifacts[0]
				art.SHA256 = strings.Repeat("f", 64)
				r.EvidenceBundles[i].Artifacts[0] = art
			}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			clone := cloneResult(t, test.base)
			test.mutate(&clone)
			if err := clone.Validate(); err == nil {
				t.Fatal("expected Validate rejection")
			}
		})
	}
}

func mutateFacts(t *testing.T, bundle *domain.EvidenceBundle, mutator func(map[string]any)) {
	t.Helper()
	var facts map[string]any
	if err := json.Unmarshal(bundle.Facts, &facts); err != nil {
		t.Fatal(err)
	}
	mutator(facts)
	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Facts = raw
}

func ptrArtifact(a domain.ArtifactRef) *domain.ArtifactRef {
	return &a
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
