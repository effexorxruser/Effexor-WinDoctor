package domain

import "fmt"

// ArtifactRef is a typed reference to case-local storage. Absolute paths are forbidden.
type ArtifactRef struct {
	ArtifactID          string `json:"artifact_id"`
	Kind                string `json:"kind"`
	RelativePath        string `json:"relative_path"`
	SHA256              string `json:"sha256"`
	SizeBytes           int64  `json:"size_bytes"`
	CreatedAt           string `json:"created_at"`
	MediaClassification string `json:"media_classification"`
}

var mediaClassifications = map[string]struct{}{
	"case_local": {},
	"technician": {},
	"ephemeral":  {},
	"export":     {},
}

var artifactKinds = map[string]struct{}{
	"log":        {},
	"json":       {},
	"binary":     {},
	"screenshot": {},
	"report":     {},
	"stdout":     {},
	"stderr":     {},
	"other":      {},
}

func (a ArtifactRef) Validate() error {
	if err := requireMatch("artifact_id", a.ArtifactID, reArtifactID); err != nil {
		return err
	}
	if err := requireEnum("kind", a.Kind, artifactKinds); err != nil {
		return err
	}
	if err := validateRelativePath("relative_path", a.RelativePath); err != nil {
		return err
	}
	if err := requireSHA256("sha256", a.SHA256); err != nil {
		return err
	}
	if a.SizeBytes < 0 {
		return fmt.Errorf("size_bytes must be >= 0")
	}
	if err := requireRFC3339("created_at", a.CreatedAt); err != nil {
		return err
	}
	if err := requireEnum("media_classification", a.MediaClassification, mediaClassifications); err != nil {
		return err
	}
	return nil
}
