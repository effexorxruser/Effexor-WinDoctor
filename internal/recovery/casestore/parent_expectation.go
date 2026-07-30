package casestore

import "fmt"

// ParentExpectationMode selects which optimistic concurrency check Commit applies.
//
// Empty strings are never used to mean both "unspecified" and "absent head".
// Callers must choose an explicit mode.
type ParentExpectationMode int

const (
	// ParentExpectationUnspecified applies no parent precondition.
	// Reserved for callers that intentionally skip CAS (not used by Coordinator writes).
	ParentExpectationUnspecified ParentExpectationMode = iota
	// ParentExpectationAbsent requires the case to have no committed head.
	ParentExpectationAbsent
	// ParentExpectationCommit requires the current head commit ID to equal CommitID.
	ParentExpectationCommit
)

// ParentExpectation is an explicit optimistic concurrency precondition for Commit.
type ParentExpectation struct {
	Mode     ParentExpectationMode
	CommitID string
}

// ExpectAbsentParent requires that no commit head exists for the case.
func ExpectAbsentParent() ParentExpectation {
	return ParentExpectation{Mode: ParentExpectationAbsent}
}

// ExpectParentCommit requires that the current head commit equals commitID.
func ExpectParentCommit(commitID string) ParentExpectation {
	return ParentExpectation{Mode: ParentExpectationCommit, CommitID: commitID}
}

func (p ParentExpectation) validate() error {
	switch p.Mode {
	case ParentExpectationUnspecified:
		return nil
	case ParentExpectationAbsent:
		if p.CommitID != "" {
			return fmt.Errorf("%w: absent parent expectation must not set CommitID", ErrInvalidArgument)
		}
		return nil
	case ParentExpectationCommit:
		if err := validateCommitID(p.CommitID); err != nil {
			return fmt.Errorf("%w: parent expectation commit id: %v", ErrInvalidArgument, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown parent expectation mode %d", ErrInvalidArgument, p.Mode)
	}
}

func (p ParentExpectation) check(chain []commitRecord) error {
	if err := p.validate(); err != nil {
		return err
	}
	actual := ""
	if len(chain) > 0 {
		actual = chain[len(chain)-1].CommitID
	}
	switch p.Mode {
	case ParentExpectationUnspecified:
		return nil
	case ParentExpectationAbsent:
		if len(chain) > 0 {
			return fmt.Errorf("%w: case already has head commit %s", ErrCaseExists, actual)
		}
		return nil
	case ParentExpectationCommit:
		if actual != p.CommitID {
			return fmt.Errorf("%w: expected parent commit %s, actual %s",
				ErrRevisionConflict, p.CommitID, actual)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown parent expectation mode %d", ErrInvalidArgument, p.Mode)
	}
}
