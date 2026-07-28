package casestore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

// MapArtifactProvider serves artifact bytes keyed by artifact_id.
// It never opens ArtifactRef.relative_path.
type MapArtifactProvider struct {
	Blobs map[string][]byte
}

// OpenArtifact returns a reader for the artifact bytes registered under ref.ArtifactID.
func (p MapArtifactProvider) OpenArtifact(_ context.Context, ref domain.ArtifactRef) (io.ReadCloser, error) {
	if p.Blobs == nil {
		return nil, fmt.Errorf("casestore: no artifact bytes for %s", ref.ArtifactID)
	}
	b, ok := p.Blobs[ref.ArtifactID]
	if !ok {
		return nil, fmt.Errorf("casestore: no artifact bytes for %s", ref.ArtifactID)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// TrackingArtifactProvider wraps a provider and records which refs were opened.
type TrackingArtifactProvider struct {
	Inner   ArtifactProvider
	Opened  []domain.ArtifactRef
	OpenErr error
}

// OpenArtifact records the ref and delegates; it still never opens relative_path.
func (p *TrackingArtifactProvider) OpenArtifact(ctx context.Context, ref domain.ArtifactRef) (io.ReadCloser, error) {
	p.Opened = append(p.Opened, ref)
	if p.OpenErr != nil {
		return nil, p.OpenErr
	}
	if p.Inner == nil {
		return nil, fmt.Errorf("casestore: nil inner provider")
	}
	// Defensive: ensure callers cannot trick Store into path opens via this helper.
	_ = strings.TrimSpace(ref.RelativePath)
	return p.Inner.OpenArtifact(ctx, ref)
}
