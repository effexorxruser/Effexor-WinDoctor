package casestore

type caseLock interface {
	Unlock() error
}
