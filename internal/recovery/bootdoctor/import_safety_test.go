package bootdoctor_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageDoesNotImportOSExecOrGateway(t *testing.T) {
	t.Parallel()
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			switch {
			case path == "os/exec", path == "os/user":
				t.Fatalf("%s imports forbidden package %s", name, path)
			case strings.Contains(path, "/gateway"), strings.Contains(path, "/agentloop"), strings.Contains(path, "/shell"):
				t.Fatalf("%s imports forbidden package %s", name, path)
			}
		}
		text := string(src)
		for _, tok := range []string{"bcdboot", "bootrec", "diskpart", "manage-bde", "powershell", "cmd.exe"} {
			if strings.Contains(strings.ToLower(text), tok) {
				t.Fatalf("%s contains repair/command token %q", name, tok)
			}
		}
	}
}
