package bootdoctor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

const (
	analyzerID      = "effexor-recovery-boot-doctor"
	analyzerVersion = "1.0.0"
	codeLimitPrefix = "finding_code:"
)

func findingIDFor(caseID, code string, targets, evidence []string) string {
	targets = uniqueSorted(targets)
	evidence = uniqueSorted(evidence)
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "bootdoctor|%s|%s|%s|", analyzerVersion, caseID, code)
	_, _ = fmt.Fprintf(h, "targets=%s|", strings.Join(targets, ","))
	_, _ = fmt.Fprintf(h, "evidence=%s", strings.Join(evidence, ","))
	sum := hex.EncodeToString(h.Sum(nil))
	return "finding-" + sum[:24]
}

func FindingCodeOf(f domain.Finding) string {
	for _, lim := range f.Limitations {
		if strings.HasPrefix(lim, codeLimitPrefix) {
			return strings.TrimPrefix(lim, codeLimitPrefix)
		}
	}
	return ""
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	set := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
