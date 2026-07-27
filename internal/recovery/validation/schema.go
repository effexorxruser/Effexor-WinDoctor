// Package validation compiles and validates Effexor Recovery JSON contracts.
package validation

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

type contractSpec struct {
	Dir  string
	File string
	ID   string
	Name string
}

var contracts = []contractSpec{
	{Dir: "common-1.0.0", File: "common.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/common-1.0.0/common.schema.json", Name: "common"},
	{Dir: "case-manifest-1.0.0", File: "case-manifest.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/case-manifest-1.0.0/case-manifest.schema.json", Name: domain.SchemaCaseManifest},
	{Dir: "target-1.0.0", File: "target.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/target-1.0.0/target.schema.json", Name: domain.SchemaTarget},
	{Dir: "evidence-bundle-1.0.0", File: "evidence-bundle.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/evidence-bundle-1.0.0/evidence-bundle.schema.json", Name: domain.SchemaEvidenceBundle},
	{Dir: "finding-1.0.0", File: "finding.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/finding-1.0.0/finding.schema.json", Name: domain.SchemaFinding},
	{Dir: "repair-plan-1.0.0", File: "repair-plan.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/repair-plan-1.0.0/repair-plan.schema.json", Name: domain.SchemaRepairPlan},
	{Dir: "operation-descriptor-1.0.0", File: "operation-descriptor.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/operation-descriptor-1.0.0/operation-descriptor.schema.json", Name: domain.SchemaOperationDescriptor},
	{Dir: "execution-event-1.0.0", File: "execution-event.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/execution-event-1.0.0/execution-event.schema.json", Name: domain.SchemaExecutionEvent},
	{Dir: "verification-report-1.0.0", File: "verification-report.schema.json", ID: "https://effexorwinpe.local/contracts/recovery/verification-report-1.0.0/verification-report.schema.json", Name: domain.SchemaVerificationReport},
}

var (
	compilerOnce sync.Once
	schemas      map[string]*jsonschema.Schema
	compileErr   error
)

func contractsRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "contracts", "recovery")), nil
}

// CompileAll loads every recovery schema and returns them keyed by schema_name
// (common is keyed as "common").
func CompileAll() (map[string]*jsonschema.Schema, error) {
	compilerOnce.Do(func() {
		root, err := contractsRoot()
		if err != nil {
			compileErr = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		compiler.AssertFormat = true
		for _, spec := range contracts {
			raw, err := os.ReadFile(filepath.Join(root, spec.Dir, spec.File))
			if err != nil {
				compileErr = err
				return
			}
			if err := compiler.AddResource(spec.ID, bytes.NewReader(raw)); err != nil {
				compileErr = fmt.Errorf("%s: %w", spec.Name, err)
				return
			}
		}
		out := make(map[string]*jsonschema.Schema, len(contracts))
		for _, spec := range contracts {
			schema, err := compiler.Compile(spec.ID)
			if err != nil {
				compileErr = fmt.Errorf("compile %s: %w", spec.Name, err)
				return
			}
			out[spec.Name] = schema
		}
		schemas = out
	})
	return schemas, compileErr
}

// ValidateJSON validates instance bytes against the named recovery schema.
func ValidateJSON(schemaName string, raw []byte) error {
	all, err := CompileAll()
	if err != nil {
		return err
	}
	schema, ok := all[schemaName]
	if !ok || schemaName == "common" {
		return fmt.Errorf("unknown recovery schema %q", schemaName)
	}
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return err
	}
	return schema.Validate(instance)
}
