package casestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func openTestStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	st, err := Open(root, Options{
		Clock:   fixedClock{t: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Entropy: bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 64)),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return st
}

func baseSnapshot(t *testing.T) Snapshot {
	t.Helper()
	return Snapshot{
		Case: domain.CaseManifest{
			SchemaName:    domain.SchemaCaseManifest,
			SchemaVersion: domain.SchemaVersion,
			CaseID:        "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			CreatedAt:     "2026-07-27T12:00:00Z",
			UpdatedAt:     "2026-07-27T12:05:00Z",
			Runtime:       "winpe",
			CurrentState:  domain.CaseStateSnapshotted,
			TargetIDs:     []string{"target-disk-nvme0n1"},
			PrivacyClass:  "standard",
		},
		Targets: []domain.Target{{
			SchemaName:    domain.SchemaTarget,
			SchemaVersion: domain.SchemaVersion,
			TargetID:      "target-disk-nvme0n1",
			TargetType:    "disk",
			DiscoveredAt:  "2026-07-27T12:00:00Z",
			DisplayName:   "NVMe Disk 0",
			StableIdentity: map[string]string{
				"disk_serial": "SN-TEST-001",
			},
			RuntimeLocators: map[string]string{"winpe_disk_number": "0"},
			Capabilities:    []string{"read_sectors"},
			Limitations:     []string{},
		}},
		EvidenceBundles: []domain.EvidenceBundle{{
			SchemaName:       domain.SchemaEvidenceBundle,
			SchemaVersion:    domain.SchemaVersion,
			EvidenceID:       "evidence-bbbbbbbbbbbbbbbbbbbbbbbb",
			CaseID:           "case-aaaaaaaaaaaaaaaaaaaaaaaa",
			TargetID:         "target-disk-nvme0n1",
			Collector:        "effexor-recovery-probe",
			CollectorVersion: "0.1.0",
			CapturedAt:       "2026-07-27T12:01:00Z",
			SourceStatus:     "ok",
			FactsSchema:      "facts.disk-inventory.v1",
			Facts:            json.RawMessage(`{"partition_count":4,"has_esp":true}`),
			Artifacts:        []domain.ArtifactRef{},
			Limitations:      []string{},
		}},
	}
}

func snapshotWithArtifact(t *testing.T, payload []byte) (Snapshot, MapArtifactProvider) {
	t.Helper()
	snap := baseSnapshot(t)
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	ref := domain.ArtifactRef{
		ArtifactID:          "artifact-111111111111111111111111",
		Kind:                "json",
		RelativePath:        "evidence/disk-inventory.json",
		SHA256:              sha,
		SizeBytes:           int64(len(payload)),
		CreatedAt:           "2026-07-27T12:01:00Z",
		MediaClassification: "case_local",
	}
	snap.EvidenceBundles[0].Artifacts = []domain.ArtifactRef{ref}
	return snap, MapArtifactProvider{Blobs: map[string][]byte{ref.ArtifactID: append([]byte(nil), payload...)}}
}

func mustCommit(t *testing.T, st *Store, snap Snapshot, provider ArtifactProvider, reason CommitReason) CommitInfo {
	t.Helper()
	info, err := st.Commit(context.Background(), CommitRequest{
		Snapshot:         snap,
		ArtifactProvider: provider,
		Reason:           reason,
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return info
}

func mutateCaseUpdatedAt(snap Snapshot, updatedAt string) Snapshot {
	snap.Case.UpdatedAt = updatedAt
	return snap
}

func readCaseFile(t *testing.T, st *Store, caseID string, parts ...string) []byte {
	t.Helper()
	p := filepath.Join(append([]string{st.caseDir(caseID)}, parts...)...)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return raw
}

type failProvider struct{}

func (failProvider) OpenArtifact(context.Context, domain.ArtifactRef) (io.ReadCloser, error) {
	return nil, io.ErrUnexpectedEOF
}
