package legacyreport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/diagnostics"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

const (
	importerName    = "effexor-recovery-legacy-importer"
	importerVersion = "1.0.0"

	factsSchemaName    = "legacy-diagnostic-report-fragment"
	factsSchemaVersion = "1.0.0"
	// FactsSchemaID is the stable facts_schema value written on EvidenceBundle.
	FactsSchemaID = "https://effexorwinpe.local/contracts/recovery/facts/legacy-diagnostic-report-fragment-1.0.0/legacy-diagnostic-report-fragment.schema.json"

	sourceSchemaName    = "diagnostic-report"
	sourceSchemaVersion = diagnostics.SchemaVersion

	limReportScoped = "identity is scoped to the imported legacy report and is not guaranteed stable across separate collection runs."
	limDriveLetters = "drive letters and mount paths are runtime locators, not stable identity."
	limDriveHealth  = "diagnostic-report 1.3.0 does not provide a reliable drive-health-to-disk relationship key."
	limBitLockerNA  = "BitLocker inventory is unavailable; volume targets were not created from diagnostic-report 1.3.0."
)

// Result is the pure import output. It never contains Findings or RepairPlans.
type Result struct {
	Case            domain.CaseManifest
	Targets         []domain.Target
	EvidenceBundles []domain.EvidenceBundle
	Warnings        []string
}

// Options configures optional import inputs.
type Options struct {
	SourceArtifact *domain.ArtifactRef
}

type importContext struct {
	report            diagnostics.Report
	rawSourceSHA256   string
	normalizedSHA256  string
	caseID            string
	capturedAt        string
	artifacts         []domain.ArtifactRef
	warnings          []string
	partitionByDisk   map[int][]string // disk_number -> partition target IDs
	partitionByLetter map[string][]string
	diskByNumber      map[int]string
}

// ImportJSON converts diagnostic-report 1.3.0 JSON into recovery domain documents.
func ImportJSON(raw []byte, options Options) (Result, error) {
	if err := validateOptions(options); err != nil {
		return Result{}, err
	}
	if err := requireSchemaVersion130(raw); err != nil {
		return Result{}, err
	}
	report, err := diagnostics.DecodeReportJSON(raw)
	if err != nil {
		return Result{}, err
	}

	normalized, err := json.Marshal(report)
	if err != nil {
		return Result{}, fmt.Errorf("marshal normalized diagnostic report: %w", err)
	}
	rawSHA := sha256Hex(raw)
	normSHA := sha256Hex(normalized)
	caseID := caseIDFromNormalizedHash(normSHA)
	capturedAt := report.CollectedAt.UTC().Format("2006-01-02T15:04:05Z07:00")

	ctx := &importContext{
		report:            report,
		rawSourceSHA256:   rawSHA,
		normalizedSHA256:  normSHA,
		caseID:            caseID,
		capturedAt:        capturedAt,
		partitionByDisk:   map[int][]string{},
		partitionByLetter: map[string][]string{},
		diskByNumber:      map[int]string{},
	}
	if options.SourceArtifact != nil {
		ctx.artifacts = []domain.ArtifactRef{*options.SourceArtifact}
	} else {
		ctx.artifacts = []domain.ArtifactRef{}
	}

	targets, bundles, err := buildTargetsAndEvidence(ctx)
	if err != nil {
		return Result{}, err
	}

	targetIDs := make([]string, 0, len(targets))
	for _, t := range targets {
		targetIDs = append(targetIDs, t.TargetID)
	}

	result := Result{
		Case: domain.CaseManifest{
			SchemaName:    domain.SchemaCaseManifest,
			SchemaVersion: domain.SchemaVersion,
			CaseID:        caseID,
			CreatedAt:     capturedAt,
			UpdatedAt:     capturedAt,
			Runtime:       mapRuntime(report.Environment.RuntimeOS),
			CurrentState:  domain.CaseStateSnapshotted,
			TargetIDs:     targetIDs,
			PrivacyClass:  mapPrivacy(report.Privacy.ContainsPersonalData),
		},
		Targets:         targets,
		EvidenceBundles: bundles,
		Warnings:        append([]string{}, ctx.warnings...),
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func validateOptions(options Options) error {
	if options.SourceArtifact == nil {
		return nil
	}
	if err := options.SourceArtifact.Validate(); err != nil {
		return fmt.Errorf("SourceArtifact: %w", err)
	}
	return nil
}

func requireSchemaVersion130(raw []byte) error {
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("probe diagnostic-report schema_version: %w", err)
	}
	version := strings.TrimSpace(probe.SchemaVersion)
	switch version {
	case diagnostics.SchemaVersion:
		return nil
	case diagnostics.SchemaVersionV12:
		return fmt.Errorf("diagnostic-report schema %s is not accepted by this importer; use an explicit versioned migration path", diagnostics.SchemaVersionV12)
	case "":
		return fmt.Errorf("diagnostic report schema_version is required")
	default:
		return fmt.Errorf("unsupported diagnostic schema %q; this importer accepts only %s", version, diagnostics.SchemaVersion)
	}
}

func mapRuntime(runtimeOS string) string {
	switch strings.ToLower(strings.TrimSpace(runtimeOS)) {
	case "winpe":
		return "winpe"
	case "windows":
		return "windows"
	default:
		return "unknown"
	}
}

func mapPrivacy(containsPersonalData bool) string {
	if containsPersonalData {
		return "elevated"
	}
	return "standard"
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
