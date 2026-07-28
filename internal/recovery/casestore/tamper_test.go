package casestore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTamperCommitSnapshotIDWithoutCommitID(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(info.Sequence, info.CommitID))
	tamperCommitField(t, path, func(m map[string]any) {
		m["snapshot_id"] = "snapshot-ffffffffffffffffffffffff"
	})
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected commit_id provenance failure")
	}
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("want ErrIntegrity, got %v", err)
	}
}

func TestTamperCommitReason(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(info.Sequence, info.CommitID))
	tamperCommitField(t, path, func(m map[string]any) {
		m["reason"] = "legacy_import"
	})
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected reason tamper failure")
	}
}

func TestTamperCommitCommittedAt(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(info.Sequence, info.CommitID))
	tamperCommitField(t, path, func(m map[string]any) {
		m["committed_at"] = "2026-07-28T13:00:00Z"
	})
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected committed_at tamper failure")
	}
}

func TestTamperCommitCaseIDMismatch(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	src := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(info.Sequence, info.CommitID))
	otherCase := "case-bbbbbbbbbbbbbbbbbbbbbbbb"
	if err := os.MkdirAll(st.commitsDir(otherCase), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["case_id"] = otherCase
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(st.commitsDir(otherCase), commitFileName(info.Sequence, info.CommitID))
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = st.loadCommitChain(otherCase)
	if err == nil {
		t.Fatal("expected case_id / commit_id mismatch")
	}
}

func TestTamperCommitManifestHash(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.commitsDir(snap.Case.CaseID), commitFileName(info.Sequence, info.CommitID))
	tamperCommitField(t, path, func(m map[string]any) {
		m["snapshot_manifest_sha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	})
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected manifest hash tamper failure")
	}
}

func TestTamperManifestContentHash(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "snapshot-manifest.json")
	tamperManifestField(t, path, func(m map[string]any) {
		m["content_sha256"] = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	})
	// Also update commit's manifest file hash so load reaches provenance check.
	rewriteCommitManifestSHA(t, st, snap.Case.CaseID, info)
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected content_sha256 mismatch")
	}
}

func TestTamperManifestSnapshotID(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	path := filepath.Join(st.snapshotDir(snap.Case.CaseID, info.SnapshotID), "snapshot-manifest.json")
	tamperManifestField(t, path, func(m map[string]any) {
		m["snapshot_id"] = "snapshot-dddddddddddddddddddddddd"
	})
	rewriteCommitManifestSHA(t, st, snap.Case.CaseID, info)
	_, _, err := st.LoadLatest(context.Background(), snap.Case.CaseID)
	if err == nil {
		t.Fatal("expected snapshot_id provenance failure")
	}
}

func TestCommitBlockedByCorruptHeadSameSnapshot(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	corruptCaseManifest(t, st, snap.Case.CaseID, info.SnapshotID)
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected corrupt history to block idempotent retry")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
}

func TestCommitBlockedByCorruptHeadDifferentSnapshot(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	corruptCaseManifest(t, st, snap.Case.CaseID, info.SnapshotID)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T15:00:00Z")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap2,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected corrupt history to block append")
	}
}

func TestCommitBlockedByMissingArtifactBlob(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	payload := []byte(`{"probe":true}`)
	snap, provider := snapshotWithArtifact(t, payload)
	info := mustCommit(t, st, snap, provider, CommitReasonCaseSnapshot)
	blob := st.blobAbsPath(snap.Case.CaseID, snap.EvidenceBundles[0].Artifacts[0].SHA256)
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot:         snap,
		ArtifactProvider: provider,
		Reason:           CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected missing blob to block retry")
	}
	_ = info
}

func TestCommitBlockedByCorruptOlderSnapshot(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	c1 := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T16:00:00Z")
	_ = mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)
	corruptCaseManifest(t, st, snap.Case.CaseID, c1.SnapshotID)
	snap3 := mutateCaseUpdatedAt(snap, "2026-07-27T17:00:00Z")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap3,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected older corrupt snapshot to block append")
	}
}

func TestVerifyCorruptCommittedNotOrphan(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	corruptCaseManifest(t, st, snap.Case.CaseID, info.SnapshotID)

	report, err := st.Verify(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != IntegrityCorrupt {
		t.Fatalf("status=%s", report.Status)
	}
	for _, o := range report.OrphanSnapshots {
		if o == info.SnapshotID {
			t.Fatal("corrupt committed snapshot must not be listed as orphan")
		}
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected errors for corrupt committed snapshot")
	}

	ins, err := st.InspectRecovery(context.Background(), snap.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ins.PublishedUncommitted {
		if p == info.SnapshotID {
			t.Fatal("corrupt committed snapshot must not be published-uncommitted")
		}
	}
	if len(ins.HashMismatches) == 0 {
		t.Fatal("expected hash mismatches")
	}
}

func TestManagedPathAncestorSymlinksRejected(t *testing.T) {
	targets := []struct {
		name string
		path func(*Store, string) string
	}{
		{"cases", func(st *Store, _ string) string { return st.casesRoot() }},
		{"case", func(st *Store, id string) string { return st.caseDir(id) }},
		{"snapshots", func(st *Store, id string) string { return st.snapshotsDir(id) }},
		{"commits", func(st *Store, id string) string { return st.commitsDir(id) }},
		{"staging", func(st *Store, id string) string { return st.stagingDir(id) }},
		{"artifacts", func(st *Store, id string) string { return st.artifactsDir(id) }},
	}
	for _, tc := range targets {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			st := openTestStore(t)
			snap := baseSnapshot(t)
			_ = mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
			target := tc.path(st, snap.Case.CaseID)
			parent := filepath.Dir(target)
			realName := filepath.Base(target)
			realPath := filepath.Join(parent, realName+".real")
			if err := os.Rename(target, realPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realPath, target); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("symlink creation requires privileges: %v", err)
				}
				t.Fatal(err)
			}
			err := st.ensureManagedPath(filepath.Join(target, "child"))
			if !errors.Is(err, ErrPathUnsafe) {
				// ensureManagedPath on the symlink itself
				err = st.ensureManagedPath(target)
			}
			if !errors.Is(err, ErrPathUnsafe) {
				t.Fatalf("want ErrPathUnsafe, got %v", err)
			}
			_, _, loadErr := st.LoadLatest(context.Background(), snap.Case.CaseID)
			if loadErr == nil && tc.name != "staging" && tc.name != "artifacts" {
				// Load walks case tree; symlink under managed dirs must fail.
				if err := st.ensureCaseTreeSafe(snap.Case.CaseID); err == nil {
					t.Fatal("expected case tree unsafe")
				}
			}
		})
	}
}

func tamperCommitField(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func tamperManifestField(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	tamperCommitField(t, path, mutate)
}

func rewriteCommitManifestSHA(t *testing.T, st *Store, caseID string, info CommitInfo) {
	t.Helper()
	manifestPath := filepath.Join(st.snapshotDir(caseID, info.SnapshotID), "snapshot-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	commitPath := filepath.Join(st.commitsDir(caseID), commitFileName(info.Sequence, info.CommitID))
	tamperCommitField(t, commitPath, func(m map[string]any) {
		m["snapshot_manifest_sha256"] = sha256Hex(raw)
		// Keep commit_id so filename still matches; provenance check should still fail
		// on commit_id recompute OR on manifest content checks after hash match.
		id, err := computeCommitID(
			caseID,
			info.Sequence,
			nil,
			info.SnapshotID,
			sha256Hex(raw),
			m["committed_at"].(string),
			m["reason"].(string),
		)
		if err != nil {
			t.Fatal(err)
		}
		m["commit_id"] = id
	})
	// Filename must match new commit_id.
	rawCommit, err := os.ReadFile(commitPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec commitRecord
	if err := json.Unmarshal(rawCommit, &rec); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(st.commitsDir(caseID), commitFileName(rec.Sequence, rec.CommitID))
	if newPath != commitPath {
		if err := os.Rename(commitPath, newPath); err != nil {
			t.Fatal(err)
		}
	}
}

func corruptCaseManifest(t *testing.T, st *Store, caseID, snapshotID string) {
	t.Helper()
	path := filepath.Join(st.snapshotDir(caseID, snapshotID), "documents", "case-manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("empty case manifest")
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = strings.TrimSpace(caseID)
}
