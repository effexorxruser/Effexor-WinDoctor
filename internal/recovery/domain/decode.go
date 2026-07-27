package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func bytesReader(raw []byte) io.Reader {
	return bytes.NewReader(raw)
}

func strictDecode(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON content")
		}
		return err
	}
	return nil
}

// DecodeAndValidateJSON decodes with unknown-field rejection then Validate().
func DecodeAndValidateJSON[T interface{ Validate() error }](raw []byte, dst *T) error {
	if err := strictDecode(raw, dst); err != nil {
		return err
	}
	return (*dst).Validate()
}
