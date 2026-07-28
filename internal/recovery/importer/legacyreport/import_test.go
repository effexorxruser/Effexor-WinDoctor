package legacyreport_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/diagnostics"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func TestImportValid130(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatalf("ImportJSON() error = %v", err)
	}
	if result.Case.CurrentState != domain.CaseStateSnapshotted {
		t.Fatalf("current_state = %q", result.Case.CurrentState)
	}
	if result.Case.Runtime != "winpe" {
		t.Fatalf("runtime = %q, want winpe", result.Case.Runtime)
	}
	if result.Case.PrivacyClass != "standard" {
		t.Fatalf("privacy_class = %q, want standard", result.Case.PrivacyClass)
	}
	if len(result.Targets) != len(result.EvidenceBundles) {
		t.Fatalf("targets=%d bundles=%d", len(result.Targets), len(result.EvidenceBundles))
	}
}

func TestRejectSchema120(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":"1.2.0","report_id":"x"}`)
	_, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err == nil || !strings.Contains(err.Error(), "1.2.0") {
		t.Fatalf("expected explicit 1.2.0 rejection, got %v", err)
	}
}

func TestRejectUnknownSchema(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema_version":"9.9.9","report_id":"x"}`)
	_, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err == nil {
		t.Fatal("expected unknown schema rejection")
	}
}

func TestRejectUnknownInputField(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["unexpected_field"] = json.RawMessage(`true`)
	mutated, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacyreport.ImportJSON(mutated, legacyreport.Options{})
	if err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestDeterministicOutput(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	a, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if !bytes.Equal(aj, bj) {
		t.Fatal("identical input produced different output")
	}
}

func TestWhitespaceDoesNotChangeNormalizedIDs(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "\t\t"); err != nil {
		t.Fatal(err)
	}
	a, err := legacyreport.ImportJSON(compact.Bytes(), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := legacyreport.ImportJSON(indented.Bytes(), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Case.CaseID != b.Case.CaseID {
		t.Fatalf("case_id changed with whitespace: %s vs %s", a.Case.CaseID, b.Case.CaseID)
	}
	for i := range a.Targets {
		if a.Targets[i].TargetID != b.Targets[i].TargetID {
			t.Fatalf("target_id[%d] changed with whitespace", i)
		}
		if a.EvidenceBundles[i].EvidenceID != b.EvidenceBundles[i].EvidenceID {
			t.Fatalf("evidence_id[%d] changed with whitespace", i)
		}
	}
}

func TestSemanticChangeChangesCaseID(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	a, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["report_id"] = "report-legacy-import-uefi-02"
	mutated, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	b, err := legacyreport.ImportJSON(mutated, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Case.CaseID == b.Case.CaseID {
		t.Fatal("semantic change did not change case_id")
	}
}

func TestStableOrderingAndOneToOneEvidence(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Targets[0].TargetType != "firmware" {
		t.Fatalf("first target type = %q", result.Targets[0].TargetType)
	}
	var sawDisk, sawPart, sawWin, sawBCD bool
	for i, target := range result.Targets {
		if result.EvidenceBundles[i].TargetID != target.TargetID {
			t.Fatalf("bundle/target order mismatch at %d", i)
		}
		switch target.TargetType {
		case "disk":
			sawDisk = true
			if sawPart || sawWin || sawBCD {
				t.Fatal("disk appeared after later entity type")
			}
		case "partition":
			sawPart = true
			if !sawDisk || sawWin || sawBCD {
				t.Fatal("partition ordering invalid")
			}
		case "windows_installation":
			sawWin = true
			if !sawPart || sawBCD {
				t.Fatal("windows installation ordering invalid")
			}
		case "boot_store":
			sawBCD = true
			if !sawWin {
				t.Fatal("boot store before windows installation")
			}
		case "volume":
			t.Fatal("unexpected volume target for BitLocker unavailable fixture")
		}
	}
	counts := map[string]int{}
	for _, bundle := range result.EvidenceBundles {
		counts[bundle.TargetID]++
	}
	for id, n := range counts {
		if n != 1 {
			t.Fatalf("target %s has %d bundles", id, n)
		}
	}
	if len(result.Targets) != len(result.EvidenceBundles) {
		t.Fatal("target/evidence count mismatch")
	}
}

func TestNoNULDriveLetterLocator(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range result.Targets {
		if target.TargetType != "partition" {
			continue
		}
		if letter, ok := target.RuntimeLocators["drive_letter"]; ok {
			if letter == "" || strings.ContainsRune(letter, 0) {
				t.Fatalf("invalid drive_letter locator %q", letter)
			}
		}
	}
}

func TestPartitionDiskRelation(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	diskByNumber := map[string]string{}
	for _, target := range result.Targets {
		if target.TargetType == "disk" {
			diskByNumber[target.RuntimeLocators["disk_number"]] = target.TargetID
		}
	}
	found := false
	for _, bundle := range result.EvidenceBundles {
		var facts map[string]any
		if err := json.Unmarshal(bundle.Facts, &facts); err != nil {
			t.Fatal(err)
		}
		if facts["entity_kind"] != "partition" {
			continue
		}
		related := toStringSlice(facts["related_target_ids"])
		wantDisk := diskByNumber[payloadDiskNumber(facts["payload"])]
		if !contains(related, wantDisk) {
			t.Fatalf("partition missing disk relation: related=%v want=%s", related, wantDisk)
		}
		found = true
	}
	if !found {
		t.Fatal("no partition facts found")
	}
}

func TestUnambiguousDriveLetterRelations(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-bitlocker-partial.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	partID := ""
	for _, target := range result.Targets {
		if target.TargetType == "partition" && target.RuntimeLocators["drive_letter"] == "C" {
			partID = target.TargetID
		}
	}
	if partID == "" {
		t.Fatal("missing C partition")
	}
	for _, bundle := range result.EvidenceBundles {
		var facts map[string]any
		_ = json.Unmarshal(bundle.Facts, &facts)
		kind, _ := facts["entity_kind"].(string)
		if kind != "windows_installation" && kind != "boot_store" && kind != "bitlocker_volume" {
			continue
		}
		related := toStringSlice(facts["related_target_ids"])
		if !contains(related, partID) {
			t.Fatalf("%s missing unambiguous C relation", kind)
		}
	}
}

func TestAmbiguousDriveLetterOmitsRelation(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	storage := report["storage"].(map[string]any)
	parts := storage["partitions"].([]any)
	parts = append(parts, map[string]any{
		"disk_number":      1,
		"partition_number": 2,
		"drive_letter":     "C",
		"size_bytes":       1000,
		"type":             "Basic",
		"is_active":        false,
	})
	storage["partitions"] = parts
	mutated, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	result, err := legacyreport.ImportJSON(mutated, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "matches") && strings.Contains(w, "partitions") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("expected ambiguous warning, got %#v", result.Warnings)
	}
	for _, bundle := range result.EvidenceBundles {
		var facts map[string]any
		_ = json.Unmarshal(bundle.Facts, &facts)
		if facts["entity_kind"] != "windows_installation" {
			continue
		}
		if len(toStringSlice(facts["related_target_ids"])) != 0 {
			t.Fatal("ambiguous windows relation should be omitted")
		}
	}
}

func TestBitLockerUnavailableCreatesNoVolume(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range result.Targets {
		if target.TargetType == "volume" {
			t.Fatal("volume target must not be created when BitLocker unavailable")
		}
	}
	firmware := result.EvidenceBundles[0]
	if !contains(firmware.Limitations, "BitLocker inventory is unavailable; volume targets were not created from diagnostic-report 1.3.0.") {
		t.Fatalf("missing bitlocker unavailable limitation: %#v", firmware.Limitations)
	}
}

func TestBitLockerPartialCreatesPartialVolumeEvidence(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-bitlocker-partial.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, bundle := range result.EvidenceBundles {
		var facts map[string]any
		_ = json.Unmarshal(bundle.Facts, &facts)
		if facts["entity_kind"] != "bitlocker_volume" {
			continue
		}
		found = true
		if bundle.SourceStatus != "partial" {
			t.Fatalf("source_status = %q, want partial", bundle.SourceStatus)
		}
	}
	if !found {
		t.Fatal("expected bitlocker volume evidence")
	}
}

func TestSourceStatusNotDerivedFromHealthWarnings(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range result.EvidenceBundles {
		var facts map[string]any
		_ = json.Unmarshal(bundle.Facts, &facts)
		kind, _ := facts["entity_kind"].(string)
		if kind == "bitlocker_volume" {
			continue
		}
		if bundle.SourceStatus != "ok" {
			t.Fatalf("%s source_status = %q; health warnings must not force partial", kind, bundle.SourceStatus)
		}
	}
}

func TestPrivacyClassMapping(t *testing.T) {
	t.Parallel()
	elevated, err := legacyreport.ImportJSON(testdata(t, "report-bitlocker-partial.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if elevated.Case.PrivacyClass != "elevated" {
		t.Fatalf("privacy_class = %q", elevated.Case.PrivacyClass)
	}
}

func TestReportScopedIdentityLimitations(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range result.Targets {
		if !contains(target.Limitations, "identity is scoped to the imported legacy report and is not guaranteed stable across separate collection runs.") {
			t.Fatalf("missing report-scoped limitation on %s", target.TargetID)
		}
		if _, ok := target.StableIdentity["legacy_report_hash"]; !ok {
			t.Fatal("missing legacy_report_hash")
		}
		if _, ok := target.StableIdentity["legacy_source_path"]; !ok {
			t.Fatal("missing legacy_source_path")
		}
		if _, ok := target.StableIdentity["legacy_entity_fingerprint"]; !ok {
			t.Fatal("missing legacy_entity_fingerprint")
		}
	}
}

func TestSHA256PresentInFacts(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	result, err := legacyreport.ImportJSON(raw, legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	if err := json.Unmarshal(result.EvidenceBundles[0].Facts, &facts); err != nil {
		t.Fatal(err)
	}
	rawHash, _ := facts["raw_source_sha256"].(string)
	normHash, _ := facts["normalized_report_sha256"].(string)
	if len(rawHash) != 64 || len(normHash) != 64 {
		t.Fatalf("invalid hashes raw=%q norm=%q", rawHash, normHash)
	}
}

func TestSourceArtifactPropagated(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "report-uefi-bitlocker-unavailable.json")
	sum := sha256.Sum256(raw)
	artifact := domain.ArtifactRef{
		ArtifactID:          "artifact-aaaaaaaaaaaaaaaaaaaaaaaa",
		Kind:                "report",
		RelativePath:        "imports/report.json",
		SHA256:              hex.EncodeToString(sum[:]),
		SizeBytes:           int64(len(raw)),
		CreatedAt:           "2026-07-27T14:00:00Z",
		MediaClassification: "case_local",
	}
	result, err := legacyreport.ImportJSON(raw, legacyreport.Options{
		SourceArtifact: &artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range result.EvidenceBundles {
		if len(bundle.Artifacts) != 1 || bundle.Artifacts[0].ArtifactID != artifact.ArtifactID {
			t.Fatalf("artifact not propagated: %#v", bundle.Artifacts)
		}
	}
}

func TestInvalidSourceArtifactRejected(t *testing.T) {
	t.Parallel()
	artifact := domain.ArtifactRef{
		ArtifactID:          "artifact-aaaaaaaaaaaaaaaaaaaaaaaa",
		Kind:                "report",
		RelativePath:        `C:\abs\report.json`,
		SHA256:              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes:           12,
		CreatedAt:           "2026-07-27T14:00:00Z",
		MediaClassification: "case_local",
	}
	_, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{
		SourceArtifact: &artifact,
	})
	if err == nil {
		t.Fatal("expected invalid SourceArtifact rejection")
	}
}

func TestGeneratedFactsPassSchema(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsBrokenCrossRefs(t *testing.T) {
	t.Parallel()
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	result.EvidenceBundles[0].TargetID = "target-does-not-exist-xxxxxxxx"
	if err := result.Validate(); err == nil {
		t.Fatal("expected Validate failure for broken target ref")
	}
}

func TestDiagnosticReportSchemaUnchanged(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "contracts", "diagnostic-report.schema.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"const": "1.3.0"`) {
		t.Fatal("diagnostic-report 1.3.0 appears altered")
	}
}

func TestNoFilesystemWrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("importer unexpectedly wrote files")
	}
}

func TestDecodeStillSupports120OutsideImporter(t *testing.T) {
	t.Parallel()
	// Ensure diagnostics migration path remains available outside this importer.
	raw := []byte(`{
		"schema_version":"1.2.0","report_id":"report000000000001","collected_at":"2026-07-22T12:00:00Z",
		"collector":{"name":"effexorwinpe-collector","version":"test"},
		"environment":{"runtime_os":"windows","runtime_arch":"amd64"},
		"hardware":{"firmware_mode":"uefi","system":{},"processor":{"cores":0,"logical_processors":0},"memory":{"total_physical_bytes":0},"network_adapters":[]},
		"storage":{"disks":[],"drive_health":[],"partitions":[],"bitlocker_volumes":[]},
		"boot":{"firmware_mode":"uefi","bcd_stores":[]},"windows_installations":[],"checks":[],
		"privacy":{"contains_personal_data":false,"excluded_by_default":[]}
	}`)
	if _, err := diagnostics.DecodeReportJSON(raw); err != nil {
		t.Fatalf("diagnostics still must accept 1.2.0 via migration: %v", err)
	}
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func payloadDiskNumber(v any) string {
	payload, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	switch n := payload["disk_number"].(type) {
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case json.Number:
		return n.String()
	case string:
		return n
	default:
		return ""
	}
}
