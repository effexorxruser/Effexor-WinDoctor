package bootdoctor_test

import (
	"reflect"
	"testing"
)

func TestAnalyzeInputOrderIndependence(t *testing.T) {
	t.Parallel()
	fix := resolveFixture(t, topologySnapshot(t, "uefi", true), testNow)
	base := analyzeFixture(t, fix, fix.Evidence.EvidenceID)

	seeds := []int64{1, 7, 42, 99, 2026}
	for _, seed := range seeds {
		seed := seed
		t.Run("", func(t *testing.T) {
			t.Parallel()
			shuffled := shuffleTopology(fix.Topology, seed)
			mutated := fix
			mutated.Topology = shuffled
			got := analyzeFixture(t, mutated, fix.Evidence.EvidenceID)
			if len(got.Findings) != len(base.Findings) {
				t.Fatalf("seed %d: finding count %d vs %d", seed, len(got.Findings), len(base.Findings))
			}
			for i := range base.Findings {
				if got.Findings[i].FindingID != base.Findings[i].FindingID {
					t.Fatalf("seed %d finding[%d] id mismatch", seed, i)
				}
				if !reflect.DeepEqual(findingCodes(got.Findings), findingCodes(base.Findings)) {
					t.Fatalf("seed %d code order mismatch: %v vs %v", seed, findingCodes(got.Findings), findingCodes(base.Findings))
				}
			}
		})
	}
}

func TestAnalyzeFindingsSortedByCodeThenID(t *testing.T) {
	t.Parallel()
	res := analyzeResolved(t, topologySnapshotDisconnected(t))
	for i := 1; i < len(res.Findings); i++ {
		prev := findingCodes(res.Findings)[i-1]
		cur := findingCodes(res.Findings)[i]
		if prev > cur {
			t.Fatalf("findings out of order at %d: %s > %s", i, prev, cur)
		}
		if prev == cur && res.Findings[i-1].FindingID > res.Findings[i].FindingID {
			t.Fatalf("finding ids out of order for code %s", prev)
		}
	}
}
