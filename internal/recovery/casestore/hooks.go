package casestore

var (
	failureCheckpoint string
	failureHook       func(string) error
)

func maybeFail(checkpoint string) error {
	if failureHook != nil {
		if err := failureHook(checkpoint); err != nil {
			return err
		}
	}
	if failureCheckpoint != "" && failureCheckpoint == checkpoint {
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
func testOnlySetFailureCheckpoint(checkpoint string) {
	failureCheckpoint = checkpoint
}

// testOnlySetFailureHook configures a custom failure hook for package tests.
func testOnlySetFailureHook(hook func(string) error) {
	failureHook = hook
}

// testOnlyClearFailureHooks resets injection state.
func testOnlyClearFailureHooks() {
	failureCheckpoint = ""
	failureHook = nil
}
