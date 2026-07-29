package casestore

func (s *Store) maybeFail(checkpoint string) error {
	if s == nil {
		return nil
	}
	if s.failureHook != nil {
		if err := s.failureHook(checkpoint); err != nil {
			return err
		}
	}
	if s.failureCheckpoint != "" && s.failureCheckpoint == checkpoint {
		return &injectedFailureError{checkpoint: checkpoint}
	}
	return nil
}

type injectedFailureError struct {
	checkpoint string
}

func (e *injectedFailureError) Error() string {
	return "casestore: injected failure at " + e.checkpoint
}

// testOnlySetFailureCheckpoint configures crash injection for package tests.
func (s *Store) testOnlySetFailureCheckpoint(checkpoint string) {
	s.failureCheckpoint = checkpoint
}

// testOnlySetFailureHook configures a custom failure hook for package tests.
func (s *Store) testOnlySetFailureHook(hook func(string) error) {
	s.failureHook = hook
}

// testOnlyClearFailureHooks resets injection state.
func (s *Store) testOnlyClearFailureHooks() {
	s.failureCheckpoint = ""
	s.failureHook = nil
}
