//go:build windows

package casestore

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestManagedPathJunctionRejected(t *testing.T) {
	st := openTestStore(t)
	snap := baseSnapshot(t)
	_ = mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)

	target := st.snapshotsDir(snap.Case.CaseID)
	parent := filepath.Dir(target)
	realName := filepath.Base(target)
	realPath := filepath.Join(parent, realName+".real")
	if err := os.Rename(target, realPath); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cmd", "/c", "mklink", "/J", target, realPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J failed: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = os.Remove(target) // remove junction, not target
		_ = os.Rename(realPath, target)
	})

	err = st.ensureManagedPath(filepath.Join(target, "child"))
	if !errors.Is(err, ErrPathUnsafe) {
		err = st.ensureManagedPath(target)
	}
	if !errors.Is(err, ErrPathUnsafe) {
		t.Fatalf("want ErrPathUnsafe for junction, got %v", err)
	}
	if err := ensureNotSymlink(target); !errors.Is(err, ErrPathUnsafe) {
		t.Fatalf("ensureNotSymlink want ErrPathUnsafe, got %v", err)
	}
}
