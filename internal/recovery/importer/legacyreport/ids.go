package legacyreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// entityFingerprint hashes a canonical JSON form of v using UseNumber so uint64
// values are not rounded through float64.
func entityFingerprint(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("fingerprint marshal: %w", err)
	}
	return fingerprintCanonicalJSON(raw)
}

func fingerprintCanonicalJSON(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var normalized any
	if err := dec.Decode(&normalized); err != nil {
		return "", fmt.Errorf("fingerprint normalize: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return "", fmt.Errorf("fingerprint normalize: %w", err)
	}
	if normalized == nil {
		return "", fmt.Errorf("fingerprint payload must not be null")
	}
	canon, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("fingerprint remarshal: %w", err)
	}
	return sha256Hex(canon), nil
}

func reportScopedIdentity(normalizedSHA256, sourcePath, fingerprint string) map[string]string {
	return map[string]string{
		"legacy_report_hash":        strings.ToLower(normalizedSHA256),
		"legacy_source_path":        sourcePath,
		"legacy_entity_fingerprint": strings.ToLower(fingerprint),
	}
}

func requireJSONEOF(dec *json.Decoder) error {
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON data")
		}
		return err
	}
	return nil
}
