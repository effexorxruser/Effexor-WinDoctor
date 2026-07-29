package coordinator

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

type randomIDSource struct {
	entropy io.Reader
}

func (s randomIDSource) NewID(prefix string) (string, error) {
	r := s.entropy
	if r == nil {
		r = rand.Reader
	}
	var b [12]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("%w: allocate id: %v", ErrInvalidArgument, err)
	}
	return prefix + "-" + hex.EncodeToString(b[:]), nil
}

func (c *Coordinator) newEventID() (string, error) {
	return c.ids.NewID("cevt")
}

func (c *Coordinator) newFindingID() (string, error) {
	return c.ids.NewID("finding")
}
