package casestore

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

var (
	storeSchemaOnce sync.Once
	storeSchemas    map[string]*jsonschema.Schema
	storeSchemaErr  error
)

func compileStoreSchemas() (map[string]*jsonschema.Schema, error) {
	storeSchemaOnce.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			storeSchemaErr = errCaller
			return
		}
		root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "contracts", "recovery", "store"))
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		compiler.AssertFormat = true
		specs := []struct {
			dir, file, id, name string
		}{
			{"snapshot-manifest-1.0.0", "snapshot-manifest.schema.json", "https://effexorwinpe.local/contracts/recovery/store/snapshot-manifest-1.0.0/snapshot-manifest.schema.json", schemaSnapshotManifest},
			{"commit-record-1.0.0", "commit-record.schema.json", "https://effexorwinpe.local/contracts/recovery/store/commit-record-1.0.0/commit-record.schema.json", schemaCommitRecord},
		}
		out := map[string]*jsonschema.Schema{}
		for _, s := range specs {
			raw, err := os.ReadFile(filepath.Join(root, s.dir, s.file))
			if err != nil {
				storeSchemaErr = err
				return
			}
			if err := compiler.AddResource(s.id, bytes.NewReader(raw)); err != nil {
				storeSchemaErr = err
				return
			}
			schema, err := compiler.Compile(s.id)
			if err != nil {
				storeSchemaErr = err
				return
			}
			out[s.name] = schema
		}
		storeSchemas = out
	})
	return storeSchemas, storeSchemaErr
}

var errCaller = errString("runtime.Caller failed")

type errString string

func (e errString) Error() string { return string(e) }

func validateStoreJSON(t *testing.T, schemaName string, raw []byte) {
	t.Helper()
	schemas, err := compileStoreSchemas()
	if err != nil {
		t.Fatal(err)
	}
	schema := schemas[schemaName]
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema %s: %v\n%s", schemaName, err, raw)
	}
}

func TestSnapshotManifestSchemaValidation(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonCaseSnapshot)
	raw := readCaseFile(t, st, snap.Case.CaseID, "snapshots", info.SnapshotID, "snapshot-manifest.json")
	validateStoreJSON(t, schemaSnapshotManifest, raw)
}

func TestCommitRecordSchemaValidation(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	snap := baseSnapshot(t)
	info := mustCommit(t, st, snap, nil, CommitReasonLegacyImport)
	raw := readCaseFile(t, st, snap.Case.CaseID, "commits", commitFileName(info.Sequence, info.CommitID))
	validateStoreJSON(t, schemaCommitRecord, raw)

	// Second commit also validates with string parent.
	snap2 := mutateCaseUpdatedAt(snap, "2026-07-27T19:00:00Z")
	info2 := mustCommit(t, st, snap2, nil, CommitReasonCaseSnapshot)
	raw2 := readCaseFile(t, st, snap.Case.CaseID, "commits", commitFileName(info2.Sequence, info2.CommitID))
	validateStoreJSON(t, schemaCommitRecord, raw2)
}

func TestSchemaHelperCompiles(t *testing.T) {
	t.Parallel()
	schemas, err := compileStoreSchemas()
	if err != nil {
		t.Fatal(err)
	}
	if schemas[schemaSnapshotManifest] == nil || schemas[schemaCommitRecord] == nil {
		t.Fatal("missing schemas")
	}
	_ = context.Background()
}
