package read

import (
	"context"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func handleVerifyStoreIntegrity(ctx context.Context, env execContext) (domain.ReadOperationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ReadOperationResult{}, err
	}
	if env.verifier == nil {
		return domain.ReadOperationResult{}, ErrMissingStoreVerifier
	}
	report, err := env.verifier.Verify(ctx, env.request.CaseID)
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	status := integrityStatus(report.Status)
	limitations := mergeLimitations(report.Warnings)
	if report.StagingEntries == nil {
		report.StagingEntries = []string{}
	}
	if report.OrphanSnapshots == nil {
		report.OrphanSnapshots = []string{}
	}
	if report.OrphanArtifacts == nil {
		report.OrphanArtifacts = []string{}
	}
	if report.TemporaryFiles == nil {
		report.TemporaryFiles = []string{}
	}
	if report.Errors == nil {
		report.Errors = []string{}
	}
	out := baseResult(env.request, domain.ObservationCaseStore, status, []string{}, limitations)
	out.ObservedAt = report.CheckedAt
	facts, err := marshalFacts(map[string]any{
		"case_id":            report.CaseID,
		"status":             report.Status,
		"commit_count":       report.CommitCount,
		"snapshot_count":     report.SnapshotCount,
		"verified_documents": report.VerifiedDocuments,
		"verified_artifacts": report.VerifiedArtifacts,
		"latest_commit":      report.LatestCommit,
		"staging_entries":    report.StagingEntries,
		"orphan_snapshots":   report.OrphanSnapshots,
		"orphan_artifacts":   report.OrphanArtifacts,
		"temporary_files":    report.TemporaryFiles,
		"errors":             report.Errors,
	})
	if err != nil {
		return domain.ReadOperationResult{}, err
	}
	out.Facts = facts
	return out, nil
}

func integrityStatus(status casestore.IntegrityStatus) domain.ReadObservationStatus {
	switch status {
	case casestore.IntegrityOK:
		return domain.ReadStatusOK
	case casestore.IntegrityDegraded:
		return domain.ReadStatusPartial
	default:
		return domain.ReadStatusError
	}
}
