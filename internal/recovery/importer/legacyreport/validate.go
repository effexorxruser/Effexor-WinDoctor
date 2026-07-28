package legacyreport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

var (
	factsSchemaOnce sync.Once
	factsSchema     *jsonschema.Schema
	factsSchemaErr  error
)

// Validate checks Result integrity and document/schema validity.
func (r Result) Validate() error {
	if err := r.Case.Validate(); err != nil {
		return fmt.Errorf("case: %w", err)
	}
	if len(r.Case.TargetIDs) != len(r.Targets) {
		return fmt.Errorf("case.target_ids length %d does not match targets length %d", len(r.Case.TargetIDs), len(r.Targets))
	}

	targetIDs := make(map[string]struct{}, len(r.Targets))
	evidenceIDs := make(map[string]struct{}, len(r.EvidenceBundles))
	bundleByTarget := make(map[string]int, len(r.EvidenceBundles))

	for i, id := range r.Case.TargetIDs {
		if i >= len(r.Targets) || r.Targets[i].TargetID != id {
			return fmt.Errorf("case.target_ids must exactly match Targets order")
		}
	}

	for i, target := range r.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		if _, dup := targetIDs[target.TargetID]; dup {
			return fmt.Errorf("duplicate target_id %q", target.TargetID)
		}
		targetIDs[target.TargetID] = struct{}{}
	}

	if len(r.EvidenceBundles) != len(r.Targets) {
		return fmt.Errorf("evidence bundle count %d does not match target count %d", len(r.EvidenceBundles), len(r.Targets))
	}

	artifactIDs := []string{}
	for i, bundle := range r.EvidenceBundles {
		if err := bundle.Validate(); err != nil {
			return fmt.Errorf("evidence_bundles[%d]: %w", i, err)
		}
		if _, dup := evidenceIDs[bundle.EvidenceID]; dup {
			return fmt.Errorf("duplicate evidence_id %q", bundle.EvidenceID)
		}
		evidenceIDs[bundle.EvidenceID] = struct{}{}
		if bundle.CaseID != r.Case.CaseID {
			return fmt.Errorf("evidence_bundles[%d] case_id mismatch", i)
		}
		if _, ok := targetIDs[bundle.TargetID]; !ok {
			return fmt.Errorf("evidence_bundles[%d] target_id %q is unknown", i, bundle.TargetID)
		}
		bundleByTarget[bundle.TargetID]++
		if bundle.TargetID != r.Targets[i].TargetID {
			return fmt.Errorf("evidence_bundles must follow Targets order")
		}
		if err := validateFactsJSON(bundle.Facts); err != nil {
			return fmt.Errorf("evidence_bundles[%d].facts: %w", i, err)
		}
		var facts factsEnvelope
		if err := json.Unmarshal(bundle.Facts, &facts); err != nil {
			return fmt.Errorf("evidence_bundles[%d].facts decode: %w", i, err)
		}
		for _, related := range facts.RelatedTargetIDs {
			if _, ok := targetIDs[related]; !ok {
				return fmt.Errorf("evidence_bundles[%d] related_target_id %q is unknown", i, related)
			}
		}
		for _, a := range bundle.Artifacts {
			artifactIDs = append(artifactIDs, a.ArtifactID)
		}
	}
	for targetID, count := range bundleByTarget {
		if count != 1 {
			return fmt.Errorf("target %q has %d evidence bundles; want exactly 1", targetID, count)
		}
	}

	refs := domain.NewCrossRefs(
		[]string{r.Case.CaseID},
		keys(targetIDs),
		keys(evidenceIDs),
		nil,
		nil,
		unique(artifactIDs),
	)
	for i, bundle := range r.EvidenceBundles {
		if err := bundle.ValidateEvidenceRefs(refs); err != nil {
			return fmt.Errorf("evidence_bundles[%d] crossrefs: %w", i, err)
		}
	}
	return nil
}

func validateFactsJSON(raw []byte) error {
	schema, err := loadFactsSchema()
	if err != nil {
		return err
	}
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return err
	}
	return schema.Validate(instance)
}

func loadFactsSchema() (*jsonschema.Schema, error) {
	factsSchemaOnce.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			factsSchemaErr = fmt.Errorf("runtime.Caller failed")
			return
		}
		path := filepath.Clean(filepath.Join(
			filepath.Dir(file),
			"..", "..", "..", "..",
			"contracts", "recovery", "facts",
			"legacy-diagnostic-report-fragment-1.0.0",
			"legacy-diagnostic-report-fragment.schema.json",
		))
		raw, err := os.ReadFile(path)
		if err != nil {
			factsSchemaErr = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		compiler.AssertFormat = true
		id := FactsSchemaID
		if err := compiler.AddResource(id, bytes.NewReader(raw)); err != nil {
			factsSchemaErr = err
			return
		}
		factsSchema, factsSchemaErr = compiler.Compile(id)
	})
	return factsSchema, factsSchemaErr
}

func keys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
