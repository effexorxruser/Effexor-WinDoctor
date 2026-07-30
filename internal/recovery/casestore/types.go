package casestore

import (
	"context"
	"io"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// Snapshot is an in-memory recovery case state ready for persistence.
type Snapshot struct {
	Case                domain.CaseManifest
	Targets             []domain.Target
	EvidenceBundles     []domain.EvidenceBundle
	Findings            []domain.Finding
	RepairPlans         []domain.RepairPlan
	ExecutionEvents     []domain.ExecutionEvent
	VerificationReports []domain.VerificationReport
	WorkflowState       *domain.CaseWorkflowState
	CoordinatorEvents   []domain.CoordinatorEvent
}

// Options configures Store open-time dependencies.
type Options struct {
	Clock   Clock
	Entropy io.Reader
}

// Clock supplies wall time for commit and manifest timestamps.
type Clock interface {
	Now() time.Time
}

// ArtifactProvider supplies artifact bytes. Store never opens ArtifactRef.relative_path.
type ArtifactProvider interface {
	OpenArtifact(ctx context.Context, ref domain.ArtifactRef) (io.ReadCloser, error)
}

// CommitReason classifies why a snapshot was committed.
type CommitReason string

const (
	CommitReasonLegacyImport CommitReason = "legacy_import"
	CommitReasonCaseSnapshot CommitReason = "case_snapshot"
)

// CommitRequest is the input to Store.Commit.
type CommitRequest struct {
	Snapshot          Snapshot
	ArtifactProvider  ArtifactProvider
	Reason            CommitReason
	ParentExpectation ParentExpectation
}

// CommitInfo describes a published (or idempotently reused) commit.
type CommitInfo struct {
	CaseID             string
	SnapshotID         string
	CommitID           string
	Sequence           uint64
	ParentCommitID     string
	CommittedAt        string
	Idempotent         bool
	DurabilityWarnings []string
}

// IntegrityStatus is the overall Verify result.
type IntegrityStatus string

const (
	IntegrityOK       IntegrityStatus = "ok"
	IntegrityDegraded IntegrityStatus = "degraded"
	IntegrityCorrupt  IntegrityStatus = "corrupt"
)

// IntegrityReport is the read-only result of Store.Verify.
type IntegrityReport struct {
	CaseID            string          `json:"case_id"`
	CheckedAt         string          `json:"checked_at"`
	LatestCommit      string          `json:"latest_commit"`
	CommitCount       int             `json:"commit_count"`
	SnapshotCount     int             `json:"snapshot_count"`
	VerifiedDocuments int             `json:"verified_documents"`
	VerifiedArtifacts int             `json:"verified_artifacts"`
	StagingEntries    []string        `json:"staging_entries"`
	OrphanSnapshots   []string        `json:"orphan_snapshots"`
	OrphanArtifacts   []string        `json:"orphan_artifacts"`
	TemporaryFiles    []string        `json:"temporary_files"`
	ValidCommitIDs    []string        `json:"valid_commit_ids,omitempty"`
	BrokenCommitTail  []string        `json:"broken_commit_tail,omitempty"`
	Warnings          []string        `json:"warnings"`
	Errors            []string        `json:"errors"`
	Status            IntegrityStatus `json:"status"`
}

// RecoveryInspection classifies store objects for technician recovery tooling.
type RecoveryInspection struct {
	CaseID                    string   `json:"case_id"`
	InspectedAt               string   `json:"inspected_at"`
	ValidCommittedSnapshots   []string `json:"valid_committed_snapshots"`
	ValidCommitIDs            []string `json:"valid_commit_ids,omitempty"`
	ReferencedFinalSnapshots  []string `json:"referenced_final_snapshots,omitempty"`
	BrokenTailSnapshots       []string `json:"broken_tail_snapshot_ids,omitempty"`
	StagingTransactions       []string `json:"staging_transactions"`
	TemporaryCommitFiles      []string `json:"temporary_commit_files"`
	PublishedUncommitted      []string `json:"published_uncommitted_snapshots"`
	UnreferencedArtifactBlobs []string `json:"unreferenced_artifact_blobs"`
	MalformedFinalCommits     []string `json:"malformed_final_commits"`
	BrokenCommitTail          []string `json:"broken_commit_tail,omitempty"`
	BrokenCommitChain         bool     `json:"broken_commit_chain"`
	MissingManifests          []string `json:"missing_manifests"`
	HashMismatches            []string `json:"hash_mismatches"`
	Warnings                  []string `json:"warnings"`
}

// CleanupReport describes what CleanupStaging removed.
type CleanupReport struct {
	CaseID             string   `json:"case_id"`
	RemovedStaging     []string `json:"removed_staging"`
	RemovedTemporary   []string `json:"removed_temporary"`
	PreservedSnapshots []string `json:"preserved_snapshots"`
	Warnings           []string `json:"warnings"`
}

// snapshotManifest is the on-disk snapshot envelope.
type snapshotManifest struct {
	SchemaName    string                  `json:"schema_name"`
	SchemaVersion string                  `json:"schema_version"`
	CaseID        string                  `json:"case_id"`
	SnapshotID    string                  `json:"snapshot_id"`
	ContentSHA256 string                  `json:"content_sha256"`
	CreatedAt     string                  `json:"created_at"`
	Documents     []snapshotDocumentEntry `json:"documents"`
	Artifacts     []snapshotArtifactEntry `json:"artifacts"`
}

type snapshotDocumentEntry struct {
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	MediaType    string `json:"media_type"`
}

type snapshotArtifactEntry struct {
	ArtifactID          string `json:"artifact_id"`
	SHA256              string `json:"sha256"`
	SizeBytes           int64  `json:"size_bytes"`
	BlobRelativePath    string `json:"blob_relative_path"`
	Kind                string `json:"kind"`
	MediaClassification string `json:"media_classification"`
}

// commitRecord is the on-disk append-only commit marker.
type commitRecord struct {
	SchemaName             string  `json:"schema_name"`
	SchemaVersion          string  `json:"schema_version"`
	CaseID                 string  `json:"case_id"`
	Sequence               uint64  `json:"sequence"`
	CommitID               string  `json:"commit_id"`
	ParentCommitID         *string `json:"parent_commit_id"`
	SnapshotID             string  `json:"snapshot_id"`
	SnapshotManifestSHA256 string  `json:"snapshot_manifest_sha256"`
	CommittedAt            string  `json:"committed_at"`
	Reason                 string  `json:"reason"`
}

const (
	schemaSnapshotManifest = "snapshot-manifest"
	schemaCommitRecord     = "commit-record"
	schemaVersion          = "1.0.0"
	mediaTypeJSON          = "application/json"
	tempSuffix             = ".casestore-tmp"
)
