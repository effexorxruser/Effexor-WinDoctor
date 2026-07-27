package domain_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

func fixturesRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "recovery"))
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{fixturesRoot(t)}, parts...)...)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func TestValidFixturesRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file string
		run  func([]byte) error
	}{
		{"case-manifest.json", func(raw []byte) error {
			var v domain.CaseManifest
			if err := domain.DecodeAndValidateJSON(raw, &v); err != nil {
				return err
			}
			out, err := json.Marshal(v)
			if err != nil {
				return err
			}
			var again domain.CaseManifest
			return domain.DecodeAndValidateJSON(out, &again)
		}},
		{"target.json", func(raw []byte) error {
			var v domain.Target
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"evidence-bundle.json", func(raw []byte) error {
			var v domain.EvidenceBundle
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"finding.json", func(raw []byte) error {
			var v domain.Finding
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"finding-insufficient.json", func(raw []byte) error {
			var v domain.Finding
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"repair-plan.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"operation-descriptor.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"execution-event.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"verification-report.json", func(raw []byte) error {
			var v domain.VerificationReport
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()
			if err := test.run(readFixture(t, "valid", test.file)); err != nil {
				t.Fatalf("valid fixture failed: %v", err)
			}
		})
	}
}

func TestInvalidFixturesRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file string
		run  func([]byte) error
	}{
		{"case-manifest-bad-enum.json", func(raw []byte) error {
			var v domain.CaseManifest
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"case-manifest-bad-timestamp.json", func(raw []byte) error {
			var v domain.CaseManifest
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"case-manifest-unknown-field.json", func(raw []byte) error {
			var v domain.CaseManifest
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"target-unknown-field.json", func(raw []byte) error {
			var v domain.Target
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"evidence-unsafe-relative-path.json", func(raw []byte) error {
			var v domain.EvidenceBundle
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"evidence-bad-sha256.json", func(raw []byte) error {
			var v domain.EvidenceBundle
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"finding-missing-evidence.json", func(raw []byte) error {
			var v domain.Finding
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"operation-raw-command.json", func(raw []byte) error {
			_, err := domain.DecodeOperationDescriptorStrict(raw)
			return err
		}},
		{"repair-plan-bad-dependency.json", func(raw []byte) error {
			var v domain.RepairPlan
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"execution-bad-enum.json", func(raw []byte) error {
			var v domain.ExecutionEvent
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
		{"verification-bad-evidence-ref.json", func(raw []byte) error {
			var v domain.VerificationReport
			return domain.DecodeAndValidateJSON(raw, &v)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.file, func(t *testing.T) {
			t.Parallel()
			if err := test.run(readFixture(t, "invalid", test.file)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestCrossReferenceValidation(t *testing.T) {
	t.Parallel()
	var finding domain.Finding
	if err := domain.DecodeAndValidateJSON(readFixture(t, "valid", "finding.json"), &finding); err != nil {
		t.Fatalf("decode finding: %v", err)
	}
	refs := domain.NewCrossRefs(
		[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
		[]string{"target-disk-nvme0n1"},
		[]string{"evidence-bbbbbbbbbbbbbbbbbbbbbbbb"},
		nil, nil, nil,
	)
	if err := finding.ValidateFindingRefs(refs); err != nil {
		t.Fatalf("ValidateFindingRefs() error = %v", err)
	}
	bad := domain.NewCrossRefs(
		[]string{"case-aaaaaaaaaaaaaaaaaaaaaaaa"},
		[]string{"target-disk-nvme0n1"},
		[]string{"evidence-000000000000000000000000"},
		nil, nil, nil,
	)
	if err := finding.ValidateFindingRefs(bad); err == nil {
		t.Fatal("expected missing evidence ref failure")
	}
}

func TestAbsolutePathRejected(t *testing.T) {
	t.Parallel()
	a := domain.ArtifactRef{
		ArtifactID:          "artifact-111111111111111111111111",
		Kind:                "log",
		RelativePath:        `C:\Windows\system32\config`,
		SHA256:              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes:           1,
		CreatedAt:           "2026-07-27T12:00:00Z",
		MediaClassification: "case_local",
	}
	if err := a.Validate(); err == nil {
		t.Fatal("expected absolute path rejection")
	}
}
