package casestore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCaseLockBlocksConcurrentWriters(t *testing.T) {
	st := openTestStore(t)
	snap := baseSnapshot(t)
	caseID := snap.Case.CaseID

	started := make(chan struct{})
	release := make(chan struct{})
	var holdErr error

	go func() {
		holdErr = st.withCaseLock(caseID, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	err := st.withCaseLock(caseID, func() error { return nil })
	if !errors.Is(err, ErrCaseLocked) {
		close(release)
		t.Fatalf("want ErrCaseLocked, got %v", err)
	}
	close(release)
	// Wait for holder to finish.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if holdErr == nil {
			// may still be running; try acquire
			if err := st.withCaseLock(caseID, func() error { return nil }); err == nil {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := st.withCaseLock(caseID, func() error { return nil }); err != nil {
		t.Fatalf("lock not released: %v (holdErr=%v)", err, holdErr)
	}
}

func TestConcurrentCommitsNoSequenceCollision(t *testing.T) {
	st := openTestStore(t)
	snapA := baseSnapshot(t)
	snapB := mutateCaseUpdatedAt(snapA, "2026-07-27T18:00:00Z")

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	infos := make(chan CommitInfo, 2)
	run := func(snap Snapshot) {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			info, err := st.Commit(context.Background(), CommitRequest{
				Snapshot: snap,
				Reason:   CommitReasonCaseSnapshot,
			})
			if errors.Is(err, ErrCaseLocked) {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if err != nil {
				errs <- err
				return
			}
			infos <- info
			return
		}
		errs <- errors.New("too many lock retries")
	}
	wg.Add(2)
	go run(snapA)
	go run(snapB)
	wg.Wait()
	close(errs)
	close(infos)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var got []CommitInfo
	for info := range infos {
		got = append(got, info)
	}
	if len(got) != 2 {
		t.Fatalf("commits=%d", len(got))
	}
	seqs := map[uint64]struct{}{}
	for _, g := range got {
		if _, ok := seqs[g.Sequence]; ok {
			t.Fatalf("sequence collision on %d", g.Sequence)
		}
		seqs[g.Sequence] = struct{}{}
	}
	chain, err := st.loadCommitChain(snapA.Case.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain len=%d", len(chain))
	}
}

func TestContextCancellationReleasesLock(t *testing.T) {
	defer testOnlyClearFailureHooks()
	st := openTestStore(t)
	snap := baseSnapshot(t)

	ctx, cancel := context.WithCancel(context.Background())
	testOnlySetFailureHook(func(checkpoint string) error {
		if checkpoint == "after_documents_written" {
			cancel()
			return context.Canceled
		}
		return nil
	})
	_, err := st.Commit(ctx, CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected cancellation")
	}
	testOnlyClearFailureHooks()

	// Lock must be free for a subsequent commit.
	info, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err != nil {
		t.Fatalf("commit after cancel: %v", err)
	}
	if info.Sequence != 1 {
		t.Fatalf("sequence=%d", info.Sequence)
	}
}

func TestHandlesClosedAfterFailure(t *testing.T) {
	defer testOnlyClearFailureHooks()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	testOnlySetFailureCheckpoint("after_staging_created")
	_, err := st.Commit(context.Background(), CommitRequest{
		Snapshot: snap,
		Reason:   CommitReasonCaseSnapshot,
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	testOnlyClearFailureHooks()
	if err := st.withCaseLock(snap.Case.CaseID, func() error { return nil }); err != nil {
		t.Fatalf("lock held after failure: %v", err)
	}
}
