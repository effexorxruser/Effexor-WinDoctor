package casestore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCommitRetriesStagingTransactionCollision(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	if _, err := st.ensureCaseDirs(snap.Case.CaseID); err != nil {
		t.Fatal(err)
	}

	first := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	second := []byte{12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	collisionName := "txn-" + "000102030405060708090a0b"
	collisionPath := filepath.Join(st.stagingDir(snap.Case.CaseID), collisionName)
	if err := os.Mkdir(collisionPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(collisionPath, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	entropyBytes := append(append([]byte{}, first...), second...)
	entropyBytes = append(entropyBytes, bytes.Repeat([]byte{0xaa, 0xbb, 0xcc, 0xdd}, 64)...)
	st.entropy = bytes.NewReader(entropyBytes)

	info, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.Sequence != 1 {
		t.Fatalf("sequence=%d", info.Sequence)
	}
	if _, err := os.Stat(collisionPath); err != nil {
		t.Fatalf("pre-existing collision dir should be preserved: %v", err)
	}
}
