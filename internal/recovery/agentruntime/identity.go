package agentruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/casestore"
)

// InputDigest computes a deterministic digest over consultation inputs.
// Timestamps are excluded.
func InputDigest(caseID, requestID, sourceCommitID, topologyID string, findingIDs []string) string {
	ids := append([]string(nil), findingIDs...)
	sort.Strings(ids)
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "agentruntime|%s|case=%s|req=%s|commit=%s|topo=%s|findings=%s",
		RuntimeVersion, caseID, requestID, sourceCommitID, topologyID, strings.Join(ids, ","))
	return hex.EncodeToString(h.Sum(nil))
}

func ConsultationID(caseID, requestID, inputDigest string) string {
	sum := sha256.Sum256([]byte("agentruntime|consultation|" + caseID + "|" + requestID + "|" + inputDigest))
	return "consult-" + hex.EncodeToString(sum[:12])
}

func HypothesisID(consultationID string, index int, code string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("hyp|%s|%d|%s", consultationID, index, code)))
	return "hyp-" + hex.EncodeToString(sum[:12])
}

func findingIDsOf(snap casestore.Snapshot) []string {
	out := make([]string, 0, len(snap.Findings))
	for _, f := range snap.Findings {
		out = append(out, f.FindingID)
	}
	sort.Strings(out)
	return out
}

func topologyIDOf(snap casestore.Snapshot) string {
	for _, e := range snap.EvidenceBundles {
		if e.FactsSchema == "windows-boot-topology" {
			var t struct {
				TopologyID string `json:"topology_id"`
			}
			if err := json.Unmarshal(e.Facts, &t); err == nil {
				return t.TopologyID
			}
		}
	}
	return ""
}
