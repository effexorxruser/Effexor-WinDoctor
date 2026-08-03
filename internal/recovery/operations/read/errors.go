package read

import "errors"

var (
	ErrUnknownOperation      = errors.New("read: unknown operation")
	ErrUnknownVersion        = errors.New("read: unknown operation version")
	ErrUnsupportedTargetType = errors.New("read: unsupported target type for operation")
	ErrTargetNotFound        = errors.New("read: target not found in snapshot")
	ErrCaseMismatch          = errors.New("read: request case_id does not match snapshot")
	ErrMalformedParameters   = errors.New("read: malformed parameters")
	ErrUnknownParameter      = errors.New("read: unknown parameter")
	ErrMissingStoreVerifier  = errors.New("read: store verifier is required")
	ErrUnresolvedEvidence    = errors.New("read: unresolved source evidence reference")
	ErrResultMismatch        = errors.New("read: result does not match request")
	ErrInvalidDescriptor     = errors.New("read: invalid operation descriptor")
	ErrDuplicateOperation    = errors.New("read: duplicate operation id and version")
	ErrMissingHandler        = errors.New("read: missing operation handler")
	ErrUndefinedTargetType   = errors.New("read: operation has no supported target types")
)
