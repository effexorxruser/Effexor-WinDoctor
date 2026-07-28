package legacyreport

import (
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
	if len(r.Targets) == 0 {
		return fmt.Errorf("targets must not be empty")
	}
	if len(r.EvidenceBundles) == 0 {
		return fmt.Errorf("evidence_bundles must not be empty")
	}
	if len(r.Case.TargetIDs) != len(r.Targets) {
		return fmt.Errorf("case.target_ids length %d does not match targets length %d", len(r.Case.TargetIDs), len(r.Targets))
	}
	if err := validateFirmwareInvariants(r); err != nil {
		return err
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
		sawEmptyArtifacts    bool
		sawNonEmptyArtifacts bool
		canonicalArtifact    *domain.ArtifactRef
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

		facts, err := decodeFactsStrict(bundle.Facts)
		if err != nil {
			return fmt.Errorf("evidence_bundles[%d].facts: %w", i, err)
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
		if !entityKindMatchesTargetType(facts.EntityKind, target.TargetType) {
			return fmt.Errorf("evidence_bundles[%d] entity_kind %q does not match target_type %q", i, facts.EntityKind, target.TargetType)
		}

		wantCaseID := caseIDFromNormalizedHash(facts.NormalizedReportSHA256)
		if r.Case.CaseID != wantCaseID || bundle.CaseID != wantCaseID {
			return fmt.Errorf("evidence_bundles[%d] case_id does not match normalized-hash provenance", i)
		}
		wantTargetID := targetIDFrom(wantCaseID, facts.SourcePath)
		if target.TargetID != wantTargetID || bundle.TargetID != wantTargetID {
			return fmt.Errorf("evidence_bundles[%d] target_id does not match provenance", i)
		}
		wantEvidenceID := evidenceIDFrom(wantCaseID, wantTargetID, factsSchemaVersion)
		if bundle.EvidenceID != wantEvidenceID {
			return fmt.Errorf("evidence_bundles[%d] evidence_id does not match provenance", i)
		}
		fp, err := entityFingerprint(facts.Payload)
		if err != nil {
			return fmt.Errorf("evidence_bundles[%d] fingerprint: %w", i, err)
		}
		if !strings.EqualFold(fp, target.StableIdentity["legacy_entity_fingerprint"]) {
			return fmt.Errorf("evidence_bundles[%d] payload fingerprint does not match stable identity", i)
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

		switch len(bundle.Artifacts) {
		case 0:
			sawEmptyArtifacts = true
		case 1:
			sawNonEmptyArtifacts = true
			art := bundle.Artifacts[0]
			if canonicalArtifact == nil {
				copyArt := art
				canonicalArtifact = &copyArt
			} else if !sameArtifactRef(*canonicalArtifact, art) {
				if canonicalArtifact.ArtifactID == art.ArtifactID {
					return fmt.Errorf("evidence_bundles[%d] diverging ArtifactRef with same artifact_id", i)
				}
				return fmt.Errorf("evidence_bundles[%d] ArtifactRef diverges across bundles", i)
			}
			artifactIDs = append(artifactIDs, art.ArtifactID)
		default:
			return fmt.Errorf("evidence_bundles[%d] must have zero or one SourceArtifact", i)
		}
	}

	if sawEmptyArtifacts && sawNonEmptyArtifacts {
		return fmt.Errorf("artifacts must be either absent in all bundles or present in every bundle")
	}
	if canonicalArtifact != nil {
		if !strings.EqualFold(canonicalArtifact.SHA256, expectedRawHash) {
			return fmt.Errorf("SourceArtifact.sha256 must match facts raw_source_sha256")
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

func validateFirmwareInvariants(r Result) error {
	firmwareCount := 0
	for _, target := range r.Targets {
		if target.TargetType == "firmware" {
			firmwareCount++
		}
	}
	if firmwareCount != 1 {
		return fmt.Errorf("result must contain exactly one firmware target, found %d", firmwareCount)
	}
	if r.Targets[0].TargetType != "firmware" {
		return fmt.Errorf("firmware target must be first")
	}
	facts, err := decodeFactsStrict(r.EvidenceBundles[0].Facts)
	if err != nil {
		return fmt.Errorf("firmware evidence facts: %w", err)
	}
	if facts.EntityKind != "firmware_environment" {
		return fmt.Errorf("firmware facts entity_kind must be firmware_environment")
	}
	return nil
}

func entityKindMatchesTargetType(kind, targetType string) bool {
	switch kind {
	case "firmware_environment":
		return targetType == "firmware"
	case "disk":
		return targetType == "disk"
	case "partition":
		return targetType == "partition"
	case "windows_installation":
		return targetType == "windows_installation"
	case "boot_store":
		return targetType == "boot_store"
	case "bitlocker_volume":
		return targetType == "volume"
	default:
		return false
	}
}

func sameArtifactRef(a, b domain.ArtifactRef) bool {
	return a.ArtifactID == b.ArtifactID &&
		a.Kind == b.Kind &&
		a.RelativePath == b.RelativePath &&
		strings.EqualFold(a.SHA256, b.SHA256) &&
		a.SizeBytes == b.SizeBytes &&
		a.CreatedAt == b.CreatedAt &&
		a.MediaClassification == b.MediaClassification
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
		return fmt.Errorf("payload must not be null")
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
