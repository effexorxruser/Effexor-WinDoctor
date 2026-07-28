package legacyreport

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

var (
	reSHA256   = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reTargetID = regexp.MustCompile(`^target-[a-z0-9-]{8,64}$`)
)

var entityKinds = map[string]struct{}{
	"firmware_environment": {},
	"disk":                 {},
	"partition":            {},
	"windows_installation": {},
	"boot_store":           {},
	"bitlocker_volume":     {},
}

// Validate checks Result integrity without reading JSON Schema from disk.
func (r Result) Validate() error {
	if err := r.Case.Validate(); err != nil {
		return fmt.Errorf("case: %w", err)
	}
	if len(r.Case.TargetIDs) != len(r.Targets) {
		return fmt.Errorf("case.target_ids length %d does not match targets length %d", len(r.Case.TargetIDs), len(r.Targets))
	}

	targetIDs := make(map[string]struct{}, len(r.Targets))
	evidenceIDs := make(map[string]struct{}, len(r.EvidenceBundles))
	bundleByTarget := make(map[string]int, len(r.EvidenceBundles))
	targetByID := make(map[string]domain.Target, len(r.Targets))

	for i, id := range r.Case.TargetIDs {
		if i >= len(r.Targets) || r.Targets[i].TargetID != id {
			return fmt.Errorf("case.target_ids must exactly match Targets order")
		}
	}

	for i, target := range r.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		if _, dup := targetIDs[target.TargetID]; dup {
			return fmt.Errorf("duplicate target_id %q", target.TargetID)
		}
		targetIDs[target.TargetID] = struct{}{}
		targetByID[target.TargetID] = target
	}

	if len(r.EvidenceBundles) != len(r.Targets) {
		return fmt.Errorf("evidence bundle count %d does not match target count %d", len(r.EvidenceBundles), len(r.Targets))
	}

	var (
		artifactIDs          []string
		expectedReportID     string
		expectedRawHash      string
		expectedNormHash     string
		expectedCollector    string
		expectedCollectorVer string
		haveFactsBaseline    bool
	)

	for i, bundle := range r.EvidenceBundles {
		if err := bundle.Validate(); err != nil {
			return fmt.Errorf("evidence_bundles[%d]: %w", i, err)
		}
		if _, dup := evidenceIDs[bundle.EvidenceID]; dup {
			return fmt.Errorf("duplicate evidence_id %q", bundle.EvidenceID)
		}
		evidenceIDs[bundle.EvidenceID] = struct{}{}
		if bundle.CaseID != r.Case.CaseID {
			return fmt.Errorf("evidence_bundles[%d] case_id mismatch", i)
		}
		if _, ok := targetIDs[bundle.TargetID]; !ok {
			return fmt.Errorf("evidence_bundles[%d] target_id %q is unknown", i, bundle.TargetID)
		}
		bundleByTarget[bundle.TargetID]++
		if bundle.TargetID != r.Targets[i].TargetID {
			return fmt.Errorf("evidence_bundles must follow Targets order")
		}
		if bundle.FactsSchema != FactsSchemaID {
			return fmt.Errorf("evidence_bundles[%d] facts_schema must be %q", i, FactsSchemaID)
		}
		if bundle.Collector != importerName {
			return fmt.Errorf("evidence_bundles[%d] collector must be %q", i, importerName)
		}
		if bundle.CollectorVersion != importerVersion {
			return fmt.Errorf("evidence_bundles[%d] collector_version must be %q", i, importerVersion)
		}
		if bundle.CapturedAt != r.Case.CreatedAt || bundle.CapturedAt != r.Case.UpdatedAt {
			return fmt.Errorf("evidence_bundles[%d] captured_at must match case timestamps", i)
		}

		var facts factsEnvelope
		if err := json.Unmarshal(bundle.Facts, &facts); err != nil {
			return fmt.Errorf("evidence_bundles[%d].facts decode: %w", i, err)
		}
		if err := facts.Validate(); err != nil {
			return fmt.Errorf("evidence_bundles[%d].facts: %w", i, err)
		}

		target := targetByID[bundle.TargetID]
		if facts.SourcePath != target.StableIdentity["legacy_source_path"] {
			return fmt.Errorf("evidence_bundles[%d] facts source_path does not match target stable identity", i)
		}
		if !strings.EqualFold(facts.NormalizedReportSHA256, target.StableIdentity["legacy_report_hash"]) {
			return fmt.Errorf("evidence_bundles[%d] normalized hash does not match target legacy_report_hash", i)
		}

		if !haveFactsBaseline {
			expectedReportID = facts.SourceReportID
			expectedRawHash = strings.ToLower(facts.RawSourceSHA256)
			expectedNormHash = strings.ToLower(facts.NormalizedReportSHA256)
			expectedCollector = facts.SourceCollector
			expectedCollectorVer = facts.SourceCollectorVersion
			haveFactsBaseline = true
		} else {
			if facts.SourceReportID != expectedReportID {
				return fmt.Errorf("evidence_bundles[%d] source_report_id is inconsistent across bundles", i)
			}
			if strings.ToLower(facts.RawSourceSHA256) != expectedRawHash {
				return fmt.Errorf("evidence_bundles[%d] raw_source_sha256 is inconsistent across bundles", i)
			}
			if strings.ToLower(facts.NormalizedReportSHA256) != expectedNormHash {
				return fmt.Errorf("evidence_bundles[%d] normalized_report_sha256 is inconsistent across bundles", i)
			}
			if facts.SourceCollector != expectedCollector {
				return fmt.Errorf("evidence_bundles[%d] source_collector is inconsistent across bundles", i)
			}
			if facts.SourceCollectorVersion != expectedCollectorVer {
				return fmt.Errorf("evidence_bundles[%d] source_collector_version is inconsistent across bundles", i)
			}
		}

		for _, related := range facts.RelatedTargetIDs {
			if _, ok := targetIDs[related]; !ok {
				return fmt.Errorf("evidence_bundles[%d] related_target_id %q is unknown", i, related)
			}
		}
		for _, a := range bundle.Artifacts {
			artifactIDs = append(artifactIDs, a.ArtifactID)
		}
	}
	for targetID, count := range bundleByTarget {
		if count != 1 {
			return fmt.Errorf("target %q has %d evidence bundles; want exactly 1", targetID, count)
		}
	}

	refs := domain.NewCrossRefs(
		[]string{r.Case.CaseID},
		keys(targetIDs),
		keys(evidenceIDs),
		nil,
		nil,
		unique(artifactIDs),
	)
	for i, bundle := range r.EvidenceBundles {
		if err := bundle.ValidateEvidenceRefs(refs); err != nil {
			return fmt.Errorf("evidence_bundles[%d] crossrefs: %w", i, err)
		}
	}
	return nil
}

// Validate checks the facts envelope without JSON Schema compilation.
func (f factsEnvelope) Validate() error {
	if f.SchemaName != factsSchemaName {
		return fmt.Errorf("schema_name must be %q", factsSchemaName)
	}
	if f.SchemaVersion != factsSchemaVersion {
		return fmt.Errorf("schema_version must be %q", factsSchemaVersion)
	}
	if f.SourceSchemaName != sourceSchemaName {
		return fmt.Errorf("source_schema_name must be %q", sourceSchemaName)
	}
	if f.SourceSchemaVersion != sourceSchemaVersion {
		return fmt.Errorf("source_schema_version must be %q", sourceSchemaVersion)
	}
	if strings.TrimSpace(f.SourceReportID) == "" {
		return fmt.Errorf("source_report_id is required")
	}
	if !reSHA256.MatchString(f.RawSourceSHA256) {
		return fmt.Errorf("raw_source_sha256 must be 64 hexadecimal characters")
	}
	if !reSHA256.MatchString(f.NormalizedReportSHA256) {
		return fmt.Errorf("normalized_report_sha256 must be 64 hexadecimal characters")
	}
	if strings.TrimSpace(f.SourceCollector) == "" {
		return fmt.Errorf("source_collector is required")
	}
	if strings.TrimSpace(f.SourceCollectorVersion) == "" {
		return fmt.Errorf("source_collector_version is required")
	}
	if strings.TrimSpace(f.SourcePath) == "" {
		return fmt.Errorf("source_path is required")
	}
	if _, ok := entityKinds[f.EntityKind]; !ok {
		return fmt.Errorf("entity_kind has unknown value %q", f.EntityKind)
	}
	if f.RelatedTargetIDs == nil {
		return fmt.Errorf("related_target_ids is required")
	}
	for i, id := range f.RelatedTargetIDs {
		if !reTargetID.MatchString(id) {
			return fmt.Errorf("related_target_ids[%d] %q does not match required pattern", i, id)
		}
	}
	if f.Limitations == nil {
		return fmt.Errorf("limitations is required")
	}
	if f.Payload == nil {
		return fmt.Errorf("payload is required")
	}
	return nil
}

func keys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
