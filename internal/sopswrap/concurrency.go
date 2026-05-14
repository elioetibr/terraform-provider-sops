package sopswrap

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// DefaultConcurrency is the default cap on parallel decrypt/encrypt calls.
// Empirically chosen to stay under the carlpett #126 threshold and play nice
// with the GPG agent.
const DefaultConcurrency = 4

// Semaphore is a thin wrapper around x/sync/semaphore.Weighted that returns
// a release function for ergonomic defer-release.
type Semaphore struct {
	w *semaphore.Weighted
}

// NewSemaphore returns a Semaphore with the given limit. limit <= 0 falls back to DefaultConcurrency.
func NewSemaphore(limit int) *Semaphore {
	if limit <= 0 {
		limit = DefaultConcurrency
	}
	return &Semaphore{w: semaphore.NewWeighted(int64(limit))}
}

// Acquire blocks until a slot is free or ctx is cancelled.
// Returns a release function. Callers should `defer release()`.
func (s *Semaphore) Acquire(ctx context.Context) (release func(), err error) {
	if err := s.w.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	return func() { s.w.Release(1) }, nil
}
