package legacyreport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func caseIDFromNormalizedHash(normalizedSHA256 string) string {
	return "case-" + strings.ToLower(normalizedSHA256[:24])
}

func targetIDFrom(caseID, sourcePath string) string {
	sum := sha256.Sum256([]byte(caseID + "\x00" + sourcePath))
	return "target-" + hex.EncodeToString(sum[:12])
}

func evidenceIDFrom(caseID, targetID, factsSchemaVersion string) string {
	sum := sha256.Sum256([]byte(caseID + "\x00" + targetID + "\x00" + factsSchemaVersion))
	return "evidence-" + hex.EncodeToString(sum[:12])
}

func entityFingerprint(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("fingerprint marshal: %w", err)
	}
	return sha256Hex(raw), nil
}

func reportScopedIdentity(normalizedSHA256, sourcePath, fingerprint string) map[string]string {
	return map[string]string{
		"legacy_report_hash":        strings.ToLower(normalizedSHA256),
		"legacy_source_path":        sourcePath,
		"legacy_entity_fingerprint": strings.ToLower(fingerprint),
	}
}
