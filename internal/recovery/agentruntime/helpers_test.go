package agentruntime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/coordinator"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (s *seqIDs) NewID(prefix string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return fmt.Sprintf("%s-%024x", prefix, s.n), nil
}

type cyclicEntropy struct {
	pattern []byte
	off     int
}

func (c *cyclicEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.pattern[c.off%len(c.pattern)]
		c.off++
	}
	return len(p), nil
}

func openRuntimeCoord(t *testing.T) *coordinator.Coordinator {
	t.Helper()
	root := t.TempDir()
	st, err := casestore.Open(root, casestore.Options{
		Clock:   fixedClock{t: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)},
		Entropy: &cyclicEntropy{pattern: []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0xaa, 0xbb}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := coordinator.New(st, coordinator.DefaultImporter{}, coordinator.Options{
		Clock: fixedClock{t: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)},
		IDs:   &seqIDs{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func reportFixture(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "importer", "legacyreport", "testdata", "report-uefi-bitlocker-unavailable.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustAnalyzedCase(t *testing.T, c *coordinator.Coordinator) coordinator.CaseView {
	t.Helper()
	view, err := c.CreateCase(context.Background(), coordinator.CreateCaseRequest{
		DiagnosticReport: reportFixture(t),
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	topo, err := c.ResolveWindowsBootTopology(context.Background(), coordinator.ResolveWindowsBootTopologyRequest{
		CaseID:           view.Snapshot.Case.CaseID,
		ExpectedCommitID: view.CommitInfo.CommitID,
		RequestID:        "acqreq-bbbbbbbbbbbbbbbbbbbbbbbb",
		Actor:            domain.ActorSystem,
	})
	if err != nil {
		t.Fatalf("ResolveWindowsBootTopology: %v", err)
	}
	analyzed, err := c.CommitBootDoctorAnalysis(context.Background(), coordinator.CommitBootDoctorAnalysisRequest{
		CaseID:           topo.CaseView.Snapshot.Case.CaseID,
		ExpectedCommitID: topo.CaseView.CommitInfo.CommitID,
		RequestID:        "acqreq-cccccccccccccccccccccccc",
		Actor:            domain.ActorDeterministicAnalyzer,
	})
	if err != nil {
		t.Fatalf("CommitBootDoctorAnalysis: %v", err)
	}
	return analyzed.CaseView
}
