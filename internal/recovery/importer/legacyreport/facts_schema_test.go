package legacyreport_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/importer/legacyreport"
)

func TestFactsSchemaAcceptsImportedFacts(t *testing.T) {
	// Not parallel: shares schema file with TestImportDoesNotRequireFactsSchemaFile.
	schema := compileFactsSchema(t)
	result, err := legacyreport.ImportJSON(testdata(t, "report-uefi-bitlocker-unavailable.json"), legacyreport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i, bundle := range result.EvidenceBundles {
		var instance any
		if err := json.Unmarshal(bundle.Facts, &instance); err != nil {
			t.Fatalf("bundle[%d]: %v", i, err)
		}
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("bundle[%d] facts schema: %v", i, err)
		}
	}
}

func compileFactsSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
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
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource(legacyreport.FactsSchemaID, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(legacyreport.FactsSchemaID)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
