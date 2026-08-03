package read

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPackageDoesNotImportOSExec(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, root, func(info os.FileInfo) bool {
		return !info.IsDir() && strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for name, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "os/exec" {
					t.Fatalf("package %q file %q imports os/exec", name, fset.File(f.Pos()).Name())
				}
			}
		}
	}
}

func TestCatalogDescriptorsForbidCommandLikeFields(t *testing.T) {
	t.Parallel()
	forbidden := []string{"command", "shell", "powershell", "argv", "executable", "script"}
	for _, entry := range catalogEntries() {
		raw, err := json.Marshal(entry.descriptor)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(raw))
		for _, word := range forbidden {
			if strings.Contains(lower, `"`+word+`"`) {
				t.Fatalf("descriptor %q contains forbidden field %q", entry.descriptor.OperationID, word)
			}
		}
	}
}

func TestReadPackageHasNoWindowsSuffixGoFiles(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_windows.go") {
			t.Fatalf("read package must not use *_windows.go filenames (use explicit names like handlers_windows_install.go): %s", name)
		}
	}
}

func TestContractSchemaRefsForbidCommandLikeTokens(t *testing.T) {
	t.Parallel()
	forbidden := []string{"command", "shell", "powershell", "argv", "executable", "script"}
	refs := []string{paramsSchemaRef, resultSchemaRef}
	for _, ref := range refs {
		lower := strings.ToLower(ref)
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Fatalf("schema ref %q contains %q", ref, word)
			}
		}
	}
}
