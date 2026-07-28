package legacyreport

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type factsEnvelope struct {
	SchemaName             string   `json:"schema_name"`
	SchemaVersion          string   `json:"schema_version"`
	SourceSchemaName       string   `json:"source_schema_name"`
	SourceSchemaVersion    string   `json:"source_schema_version"`
	SourceReportID         string   `json:"source_report_id"`
	RawSourceSHA256        string   `json:"raw_source_sha256"`
	NormalizedReportSHA256 string   `json:"normalized_report_sha256"`
	SourceCollector        string   `json:"source_collector"`
	SourceCollectorVersion string   `json:"source_collector_version"`
	SourcePath             string   `json:"source_path"`
	EntityKind             string   `json:"entity_kind"`
	Payload                any      `json:"payload"`
	RelatedTargetIDs       []string `json:"related_target_ids"`
	Limitations            []string `json:"limitations"`
}

func buildFacts(ctx *importContext, ent orderedEntity, related []string, limitations []string) (factsEnvelope, error) {
	relatedCopy := append([]string{}, related...)
	if relatedCopy == nil {
		relatedCopy = []string{}
	}
	limCopy := append([]string{}, limitations...)
	if limCopy == nil {
		limCopy = []string{}
	}
	if ent.payload == nil {
		return factsEnvelope{}, fmt.Errorf("payload must not be null")
	}
	return factsEnvelope{
		SchemaName:             factsSchemaName,
		SchemaVersion:          factsSchemaVersion,
		SourceSchemaName:       sourceSchemaName,
		SourceSchemaVersion:    sourceSchemaVersion,
		SourceReportID:         ctx.report.ReportID,
		RawSourceSHA256:        ctx.rawSourceSHA256,
		NormalizedReportSHA256: ctx.normalizedSHA256,
		SourceCollector:        ctx.report.Collector.Name,
		SourceCollectorVersion: ctx.report.Collector.Version,
		SourcePath:             ent.sourcePath,
		EntityKind:             ent.entityKind,
		Payload:                ent.payload,
		RelatedTargetIDs:       relatedCopy,
		Limitations:            limCopy,
	}, nil
}

// decodeFactsStrict decodes a facts envelope with unknown-field rejection and
// UseNumber so payload numerics keep integer precision. payload remains an
// intentional extension point but must not be JSON null.
func decodeFactsStrict(raw []byte) (factsEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var out factsEnvelope
	if err := dec.Decode(&out); err != nil {
		return factsEnvelope{}, fmt.Errorf("decode facts: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return factsEnvelope{}, fmt.Errorf("decode facts: %w", err)
	}
	if out.Payload == nil {
		return factsEnvelope{}, fmt.Errorf("payload must not be null")
	}
	return out, nil
}
