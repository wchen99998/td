package crypto

import (
	"context"
	"errors"
	"testing"
)

func TestSingleMessageOnlySkipsScheduler(t *testing.T) {
	b := NewBatcher(&BatchingOptions{SingleMessageOnly: true, MinBytes: 16})
	b.Start(context.Background())
	defer b.Close()
	if b.started || b.jobs != nil || b.slots != nil || b.done != nil {
		t.Fatal("single-message mode allocated or started a scheduler")
	}
	var jobs []*batchTestJob
	for i := range 8 {
		jobs = append(jobs, submitJob(b, context.Background(), i, 64<<10, i%2 != 0))
	}
	for _, job := range jobs {
		checkJob(t, job)
	}
	s := b.Stats()
	if !s.Enabled || s.BatchingEnabled || s.SingleMessages != 8 || s.BatchedMessages != 0 || s.QueueWaitNS != 0 || s.PartialFlushes != 0 || s.Pending != 0 {
		t.Fatalf("single-message work entered the scheduler: %+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.crypt(ctx, [32]byte{}, [32]byte{}, nil, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	b.Close()
	if err := b.crypt(context.Background(), [32]byte{}, [32]byte{}, nil, nil, false); !errors.Is(err, ErrBatcherClosed) {
		t.Fatalf("shutdown: %v", err)
	}
}
