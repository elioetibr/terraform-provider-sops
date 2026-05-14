package sopswrap_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elioetibr/terraform-provider-sops/internal/sopswrap"
)

func TestSemaphore_RespectsLimit(t *testing.T) {
	t.Parallel()
	sem := sopswrap.NewSemaphore(2)

	var concurrent int32
	var peak int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := sem.Acquire(context.Background())
			require.NoError(t, err)
			defer rel()

			now := atomic.AddInt32(&concurrent, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if now <= p || atomic.CompareAndSwapInt32(&peak, p, now) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&concurrent, -1)
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, atomic.LoadInt32(&peak), int32(2),
		"peak concurrency must not exceed limit")
}

func TestSemaphore_ZeroLimitUsesDefault(t *testing.T) {
	t.Parallel()
	sem := sopswrap.NewSemaphore(0)
	rel, err := sem.Acquire(context.Background())
	require.NoError(t, err)
	rel()
}
