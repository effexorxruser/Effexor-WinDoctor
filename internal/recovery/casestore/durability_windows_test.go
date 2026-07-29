//go:build windows

package casestore

import "testing"

func TestCommitReportsWindowsDirectoryDurabilityWarnings(t *testing.T) {
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	if len(info.DurabilityWarnings) == 0 {
		t.Fatal("expected Windows directory durability warnings")
	}
}
