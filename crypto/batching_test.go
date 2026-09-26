package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gotd/ige"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/testutil"
)

// Hold worker launch so admission, cancellation and queue saturation do not
// depend on whether four goroutines happen to be scheduled within one timer tick.
func heldBatcher(t *testing.T, maxPending int) (*Batcher, func()) {
	t.Helper()
	b := NewBatcher(&BatchingOptions{MinBytes: 16, MaxPending: maxPending, MaxWait: time.Millisecond})
	b.available = true // exercise the scheduler even on the portable backend
	ctx, cancel := context.WithCancel(context.Background())
	b.started, b.cancel = true, cancel
	start := sync.OnceFunc(func() { go b.run(ctx) })
	t.Cleanup(func() { start(); b.Close() })
	return b, start
}

func waitPending(t *testing.T, b *Batcher, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for b.Stats().Pending != n {
		if time.Now().After(deadline) {
			t.Fatalf("pending=%d, want %d", b.Stats().Pending, n)
		}
		runtime.Gosched()
	}
}

func result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("crypto operation did not release its buffers")
		return nil
	}
}

type batchTestJob struct {
	key, iv        [32]byte
	src, dst, want []byte
	decrypt        bool
	done           chan error
}

func submitJob(b *Batcher, ctx context.Context, seed, size int, decrypt bool) *batchTestJob {
	j := &batchTestJob{src: make([]byte, size), dst: make([]byte, size), want: make([]byte, size), decrypt: decrypt, done: make(chan error, 1)}
	for i := range j.key {
		j.key[i], j.iv[i] = byte(seed+i*3), byte(seed+i*7)
	}
	for i := range j.src {
		j.src[i] = byte(seed + i)
	}
	c, _ := aes.NewCipher(j.key[:])
	if decrypt {
		ige.DecryptBlocks(c, j.iv[:], j.want, j.src)
	} else {
		ige.EncryptBlocks(c, j.iv[:], j.want, j.src)
	}
	go func() { j.done <- b.crypt(ctx, j.key, j.iv, j.dst, j.src, decrypt) }()
	return j
}

func checkJob(t *testing.T, j *batchTestJob) {
	t.Helper()
	if err := result(t, j.done); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j.dst, j.want) {
		t.Fatal("ciphertext/plaintext differs from legacy IGE")
	}
}

func TestBatcherIndependentKeysAndDirections(t *testing.T) {
	b, start := heldBatcher(t, 16)
	var jobs []*batchTestJob
	for i := range 8 {
		jobs = append(jobs, submitJob(b, context.Background(), i+1, 4096, i >= 4))
	}
	waitPending(t, b, 8)
	start()
	for _, job := range jobs {
		checkJob(t, job)
	}
	s := b.Stats()
	if s.EncryptBatches != 1 || s.DecryptBatches != 1 || s.BatchedMessages != 8 || s.SingleMessages != 0 || s.BatchedBytes != 8*4096 || s.Pending != 0 {
		t.Fatalf("unexpected stats: %+v", s)
	}
}

func TestBatcherMixedSizesAndPartialFlush(t *testing.T) {
	b, start := heldBatcher(t, 16)
	var jobs []*batchTestJob
	for i := range 4 {
		jobs = append(jobs, submitJob(b, context.Background(), i, 64, false))
	}
	jobs = append(jobs, submitJob(b, context.Background(), 10, 128<<10, false))
	jobs = append(jobs, submitJob(b, context.Background(), 11, 64, true))
	waitPending(t, b, 6)
	start()
	for _, job := range jobs {
		checkJob(t, job)
	}
	s := b.Stats()
	if s.EncryptBatches != 1 || s.DecryptBatches != 0 || s.SingleMessages != 2 || s.PartialFlushes != 2 {
		t.Fatalf("unexpected mixed-size stats: %+v", s)
	}
}

func TestBatcherNearbyLengthsShareBatch(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		b, start := heldBatcher(t, 4)
		var jobs []*batchTestJob
		for i, size := range []int{(512 << 10) + 16, (512 << 10) + 32, (512 << 10) + 64, (512 << 10) + 1024} {
			jobs = append(jobs, submitJob(b, context.Background(), i, size, decrypt))
		}
		waitPending(t, b, 4)
		start()
		for _, job := range jobs {
			checkJob(t, job)
		}
		if s := b.Stats(); s.BatchedMessages != 4 || s.SingleMessages != 0 {
			t.Fatalf("nearby padded lengths failed to batch: %+v", s)
		}
	}
}

func TestBatcherPartialRelinquishesBuffersToOriginalCaller(t *testing.T) {
	b := NewBatcher(&BatchingOptions{})
	jobs := make([]*cryptoJob, 3)
	for i := range jobs {
		jobs[i] = &cryptoJob{ctx: context.Background(), src: make([]byte, 16), dst: make([]byte, 16), queued: time.Now(), done: make(chan error, 1)}
	}
	b.execute(jobs)
	for _, job := range jobs {
		if err := result(t, job.done); err != errRunOnCaller {
			t.Fatalf("partial job executed on worker: %v", err)
		}
		if !bytes.Equal(job.dst, make([]byte, 16)) {
			t.Fatal("worker wrote a relinquished partial-job buffer")
		}
	}
	if s := b.Stats(); s.SingleMessages != 0 || s.BatchedMessages != 0 {
		t.Fatalf("partial work serialized on worker: %+v", s)
	}
}

func TestBatcherCancellationWaitsForOwnershipRelease(t *testing.T) {
	b, start := heldBatcher(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	job := submitJob(b, ctx, 1, 64, false)
	waitPending(t, b, 1)
	cancel()
	select {
	case <-job.done:
		t.Fatal("returned while queued worker still owns buffers")
	default:
	}
	start()
	if err := result(t, job.done); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if !bytes.Equal(job.dst, make([]byte, len(job.dst))) || b.Stats().Canceled != 1 || b.Stats().Pending != 0 {
		t.Fatalf("canceled job was executed: %+v", b.Stats())
	}
	// Reuse immediately after return, while the scheduler is still running.
	for i := range job.src {
		job.src[i], job.dst[i] = 42, 17
	}
}

func TestBatcherQueueFullUsesImmediateSingle(t *testing.T) {
	b, start := heldBatcher(t, 4)
	var jobs []*batchTestJob
	for i := range 4 {
		jobs = append(jobs, submitJob(b, context.Background(), i, 64, false))
	}
	waitPending(t, b, 4)
	checkJob(t, submitJob(b, context.Background(), 9, 64, false))
	if s := b.Stats(); s.QueueFull != 1 || s.SingleMessages != 1 || s.Pending != 4 {
		t.Fatalf("queue was not bounded: %+v", s)
	}
	start()
	for _, job := range jobs {
		checkJob(t, job)
	}
}

func TestBatcherCloseReleasesQueuedJobs(t *testing.T) {
	b, start := heldBatcher(t, 4)
	job := submitJob(b, context.Background(), 1, 64, false)
	waitPending(t, b, 1)
	closed := make(chan error, 1)
	go func() { b.Close(); closed <- nil }()
	for !b.closed.Load() {
		runtime.Gosched()
	}
	start()
	if err := result(t, job.done); !errors.Is(err, ErrBatcherClosed) {
		t.Fatalf("closed job: %v", err)
	}
	if err := result(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := b.crypt(context.Background(), [32]byte{}, [32]byte{}, make([]byte, 16), make([]byte, 16), false); !errors.Is(err, ErrBatcherClosed) {
		t.Fatalf("accepted work after close: %v", err)
	}
	b.Close() // idempotent
}

func TestBatcherImmediatePaths(t *testing.T) {
	for _, mode := range []string{"unstarted", "below-threshold", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			b := NewBatcher(&BatchingOptions{MinBytes: 1024})
			b.available = mode != "unsupported"
			defer b.Close()
			if mode != "unstarted" {
				b.Start(context.Background())
			}
			size := 2048
			if mode == "below-threshold" {
				size = 16
			}
			checkJob(t, submitJob(b, context.Background(), 1, size, false))
			if s := b.Stats(); s.SingleMessages != 1 || s.Pending != 0 || s.QueueWaitNS != 0 {
				t.Fatalf("immediate path queued work: %+v", s)
			}
		})
	}
}

func TestCipherBatchingOptOutRestoresLegacy(t *testing.T) {
	b := NewBatcher(&BatchingOptions{})
	c := NewClientCipher(testutil.ZeroRand{}).WithBatcher(b)
	if c.batcher != b {
		t.Fatal("batcher not attached")
	}
	for _, disabled := range []*Batcher{nil, NewBatcher(nil)} {
		if c.WithBatcher(disabled).batcher != nil {
			t.Fatal("nil/disabled option retained optimized path")
		}
	}
}

func TestBatchedCipherPreservesMessageAuthentication(t *testing.T) {
	b := NewBatcher(&BatchingOptions{MinBytes: 16})
	b.available = true
	b.Start(context.Background())
	defer b.Close()
	client := NewClientCipher(testutil.ZeroRand{}).WithBatcher(b)
	server := NewServerCipher(testutil.ZeroRand{})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			payload := bytes.Repeat([]byte{byte(i)}, 4096+16*(i%2))
			data := EncryptedMessageData{SessionID: int64(i + 1), MessageDataLen: int32(len(payload)), MessageDataWithPadding: payload}
			var buf bin.Buffer
			if err := client.EncryptContext(context.Background(), testAuthKey, data, &buf); err != nil {
				t.Error(err)
				return
			}
			decoded, err := server.DecryptFromBuffer(testAuthKey, &buf)
			if err != nil || !bytes.Equal(decoded.Data(), payload) || decoded.SessionID != data.SessionID {
				t.Errorf("packet changed: %v", err)
			}
			if err := server.Encrypt(testAuthKey, data, &buf); err != nil {
				t.Error(err)
				return
			}
			encoded := bytes.Clone(buf.Buf)
			decoded, err = client.DecryptFromBufferContext(context.Background(), testAuthKey, &buf)
			if err != nil || !bytes.Equal(decoded.Data(), payload) {
				t.Errorf("decrypt changed: %v", err)
			}
			encoded[len(encoded)-1] ^= 1
			if _, err := client.DecryptFromBufferContext(context.Background(), testAuthKey, &bin.Buffer{Buf: encoded}); err == nil {
				t.Error("accepted unauthenticated ciphertext")
			}
		})
	}
	wg.Wait()
}

func TestBatcherConcurrentShutdown(t *testing.T) {
	for trial := range 20 {
		t.Run(fmt.Sprint(trial), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			b := NewBatcher(&BatchingOptions{MinBytes: 16, MaxPending: 4})
			b.available = true
			b.Start(ctx)
			var wg sync.WaitGroup
			for range 12 {
				wg.Go(func() {
					err := b.crypt(ctx, [32]byte{}, [32]byte{}, make([]byte, 4096), make([]byte, 4096), false)
					if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrBatcherClosed) {
						t.Error(err)
					}
				})
			}
			cancel()
			b.Close()
			wg.Wait()
			if b.Stats().Pending != 0 {
				t.Fatal("retained pending jobs")
			}
		})
	}
}
