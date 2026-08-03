package legacyreport

import "encoding/json"

// FactsEnvelope is the immutable read-only legacy facts document shape.
type FactsEnvelope struct {
	SchemaName             string          `json:"schema_name"`
	SchemaVersion          string          `json:"schema_version"`
	SourceSchemaName       string          `json:"source_schema_name"`
	SourceSchemaVersion    string          `json:"source_schema_version"`
	SourceReportID         string          `json:"source_report_id"`
	RawSourceSHA256        string          `json:"raw_source_sha256"`
	NormalizedReportSHA256 string          `json:"normalized_report_sha256"`
	SourceCollector        string          `json:"source_collector"`
	SourceCollectorVersion string          `json:"source_collector_version"`
	SourcePath             string          `json:"source_path"`
	EntityKind             string          `json:"entity_kind"`
	Payload                json.RawMessage `json:"payload"`
	RelatedTargetIDs       []string        `json:"related_target_ids"`
	Limitations            []string        `json:"limitations"`
}

// DecodeFactsEnvelopeStrict decodes a legacy facts envelope with unknown-field
// rejection and json.Number precision. Payload remains typed JSON bytes for
// callers; null payload is rejected.
func DecodeFactsEnvelopeStrict(raw []byte) (FactsEnvelope, error) {
	env, err := decodeFactsStrict(raw)
	if err != nil {
		return FactsEnvelope{}, err
	}
	payloadRaw, err := json.Marshal(env.Payload)
	if err != nil {
		return FactsEnvelope{}, err
	}
	return FactsEnvelope{
		SchemaName:             env.SchemaName,
		SchemaVersion:          env.SchemaVersion,
		SourceSchemaName:       env.SourceSchemaName,
		SourceSchemaVersion:    env.SourceSchemaVersion,
		SourceReportID:         env.SourceReportID,
		RawSourceSHA256:        env.RawSourceSHA256,
		NormalizedReportSHA256: env.NormalizedReportSHA256,
		SourceCollector:        env.SourceCollector,
		SourceCollectorVersion: env.SourceCollectorVersion,
		SourcePath:             env.SourcePath,
		EntityKind:             env.EntityKind,
		Payload:                payloadRaw,
		RelatedTargetIDs:       append([]string(nil), env.RelatedTargetIDs...),
		Limitations:            append([]string(nil), env.Limitations...),
	}, nil
}
