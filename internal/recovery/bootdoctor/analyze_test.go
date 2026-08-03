package bootdoctor_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/bootdoctor"
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

var typedWorkflowRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

func TestAnalyzeDeterministicRepeat(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "uefi", true)
	a := analyzeResolved(t, snap)
	b := analyzeResolved(t, snap)
	if len(a.Findings) != len(b.Findings) {
		t.Fatalf("finding count %d vs %d", len(a.Findings), len(b.Findings))
	}
	for i := range a.Findings {
		if a.Findings[i].FindingID != b.Findings[i].FindingID {
			t.Fatalf("finding[%d] id mismatch: %s vs %s", i, a.Findings[i].FindingID, b.Findings[i].FindingID)
		}
		if bootdoctor.FindingCodeOf(a.Findings[i]) != bootdoctor.FindingCodeOf(b.Findings[i]) {
			t.Fatalf("finding[%d] code mismatch", i)
		}
	}
}

func TestAnalyzeTimestampIndependence(t *testing.T) {
	t.Parallel()
	snap := topologySnapshot(t, "uefi", true)
	early := resolveFixture(t, snap, time.Date(2026, 7, 27, 12, 10, 0, 0, time.UTC))
	late := resolveFixture(t, snap, time.Date(2026, 8, 1, 18, 30, 0, 0, time.UTC))
	if early.Topology.GeneratedAt == late.Topology.GeneratedAt {
		t.Fatal("generated_at should differ across Now values")
	}
	if early.Topology.TopologyID != late.Topology.TopologyID {
		t.Fatalf("topology id should ignore generated_at: %s vs %s", early.Topology.TopologyID, late.Topology.TopologyID)
	}
	a := analyzeFixture(t, early, early.Evidence.EvidenceID)
	b := analyzeFixture(t, late, late.Evidence.EvidenceID)
	if len(a.Findings) != len(b.Findings) {
		t.Fatalf("finding count %d vs %d", len(a.Findings), len(b.Findings))
	}
	for i := range a.Findings {
		if a.Findings[i].FindingID != b.Findings[i].FindingID {
			t.Fatalf("finding[%d] id changed with generated_at: %s vs %s", i, a.Findings[i].FindingID, b.Findings[i].FindingID)
		}
	}
}

func TestFindingCodeOfPresentInLimitations(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshot(t, "uefi", true))
	for _, f := range res.Findings {
		code := bootdoctor.FindingCodeOf(f)
		if code == "" {
			t.Fatalf("finding %s missing finding_code limitation", f.FindingID)
		}
		want := "finding_code:" + code
		found := false
		for _, lim := range f.Limitations {
			if lim == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("finding %s limitations missing %q: %v", f.FindingID, want, f.Limitations)
		}
	}
}

func TestFindingsUseTypedWorkflowsOnly(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshot(t, "uefi", true))
	for _, f := range res.Findings {
		raw, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, forbidden := range []string{"cmd.exe", "powershell", "/c ", "os/exec"} {
			if strings.Contains(strings.ToLower(text), forbidden) {
				t.Fatalf("finding %s contains forbidden field hint %q", f.FindingID, forbidden)
			}
		}
		for _, wf := range f.RecommendedWorkflows {
			if !typedWorkflowRE.MatchString(wf) {
				t.Fatalf("finding %s workflow %q is not a typed operation id", f.FindingID, wf)
			}
		}
	}
}

func TestAnalyzeRejectsUnknownEvidenceRef(t *testing.T) {
	t.Parallel()
	fix := resolveFixture(t, topologySnapshot(t, "uefi", true), testNow)
	_, err := bootdoctor.Analyze(bootdoctor.Input{
		CaseID:           testCaseID,
		Topology:         fix.Topology,
		Targets:          fix.Snap.Targets,
		KnownEvidenceIDs: []string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
		KnownTargetIDs:   targetIDsFromSnap(fix.Snap),
	})
	if err == nil {
		t.Fatal("expected unknown evidence error")
	}
	if !strings.Contains(err.Error(), "not in known evidence set") && !strings.Contains(err.Error(), "unknown evidence") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyzeRejectsUnknownTargetRef(t *testing.T) {
	t.Parallel()
	fix := resolveFixture(t, topologySnapshot(t, "uefi", true), testNow)
	_, err := bootdoctor.Analyze(bootdoctor.Input{
		CaseID:             testCaseID,
		Topology:           fix.Topology,
		TopologyEvidenceID: fix.Evidence.EvidenceID,
		Targets:            fix.Snap.Targets,
		KnownEvidenceIDs:   append(evidenceIDsFromSnap(fix.Snap), fix.Evidence.EvidenceID),
		KnownTargetIDs:     []string{"target-firmware-system"},
	})
	if err == nil {
		t.Fatal("expected unknown target error")
	}
	if !strings.Contains(err.Error(), "unknown target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWindowsMissingSuppressesBCDMembershipFindings(t *testing.T) {
	t.Parallel()
	snap := snapshotWithoutWindows(t, topologySnapshot(t, "uefi", true))
	res := analyzeResolved(t, snap)
	assertHasCode(t, res.Findings, bootdoctor.CodeWindowsInstallationMissing)
	for _, code := range []string{
		bootdoctor.CodeBCDMembershipUnknown,
		bootdoctor.CodeBCDWindowsEntryMissing,
		bootdoctor.CodeBCDPointsToUnknownInstallation,
		bootdoctor.CodeWindowsPartitionRelationUnknown,
		bootdoctor.CodeWindowsSystemDiskRelationUnknown,
		bootdoctor.CodeWindowsInstallationIncomplete,
	} {
		assertLacksCode(t, res.Findings, code)
	}
}

func TestAnalyzeRequiresCaseID(t *testing.T) {
	t.Parallel()
	fix := resolveFixture(t, topologySnapshot(t, "uefi", true), testNow)
	_, err := bootdoctor.Analyze(bootdoctor.Input{
		Topology: fix.Topology,
		Targets:  fix.Snap.Targets,
	})
	if err == nil || !strings.Contains(err.Error(), "case_id") {
		t.Fatalf("got %v", err)
	}
}

func TestAnalyzeRejectsInvalidTopology(t *testing.T) {
	t.Parallel()
	topo := domain.WindowsBootTopology{}
	_, err := bootdoctor.Analyze(bootdoctor.Input{
		CaseID:   testCaseID,
		Topology: topo,
	})
	if err == nil || !strings.Contains(err.Error(), "topology") {
		t.Fatalf("got %v", err)
	}
}
