package crypto

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gotd/ige"
)

// BatchingOptions enables AES-IGE acceleration and bounded batching of independent
// MTProto messages. A nil option keeps the original cipher implementation.
type BatchingOptions struct {
	// MinBytes is the minimum padded message size to queue. Default: 64 KiB.
	MinBytes int
	// MaxPending bounds queued and worker-executed messages. Default: 64.
	// A full queue uses the single-message implementation immediately.
	// Immediate and partial fallbacks run on their existing caller goroutines.
	MaxPending int
	// MaxWait is the maximum intentional wait for a full batch. Default: 1 ms.
	// Negative values only batch jobs already ready. Values above 1 ms are clamped.
	MaxWait time.Duration
}

// BatchStats describes local cryptographic work, not network transfer speed.
type BatchStats struct {
	Enabled         bool   `json:"enabled"`
	SIMD            bool   `json:"simd"`
	BatchSIMD       bool   `json:"batch_simd"`
	EncryptBatches  uint64 `json:"encrypt_batches"`
	DecryptBatches  uint64 `json:"decrypt_batches"`
	BatchedMessages uint64 `json:"batched_messages"`
	BatchedBytes    uint64 `json:"batched_bytes"`
	SingleMessages  uint64 `json:"single_messages"`
	SingleBytes     uint64 `json:"single_bytes"`
	EncryptMessages uint64 `json:"encrypt_messages"`
	DecryptMessages uint64 `json:"decrypt_messages"`
	EncryptBytes    uint64 `json:"encrypt_bytes"`
	DecryptBytes    uint64 `json:"decrypt_bytes"`
	QueueFull       uint64 `json:"queue_full"`
	PartialFlushes  uint64 `json:"partial_flushes"`
	Canceled        uint64 `json:"canceled"`
	QueueWaitNS     uint64 `json:"queue_wait_ns"`
	MaxQueueWaitNS  uint64 `json:"max_queue_wait_ns"`
	Pending         int64  `json:"pending"`
}

type batchCounters struct {
	encryptBatches, decryptBatches, batchedMessages, batchedBytes atomic.Uint64
	singleMessages, singleBytes                                   atomic.Uint64
	encryptMessages, decryptMessages, encryptBytes, decryptBytes  atomic.Uint64
	queueFull, partialFlushes, canceled, queueWaitNS, maxWaitNS   atomic.Uint64
	pending                                                       atomic.Int64
}

// ErrBatcherClosed indicates that the owning client has stopped.
var ErrBatcherClosed = errors.New("crypto batcher closed")

// The worker has relinquished all buffers. The waiting caller performs this
// partial job itself, retaining ordinary multicore concurrency without spawning
// another goroutine or returning to its buffer owner prematurely.
var errRunOnCaller = errors.New("crypto batch single-message fallback")

// Batcher is a client-owned AES-IGE scheduler. Constructing one starts no
// goroutines. Start binds its worker to the client lifetime; Close waits for all
// queued buffers to be relinquished. It is safe for concurrent use.
type Batcher struct {
	opts      BatchingOptions
	enabled   bool
	simd      bool
	available bool
	stats     batchCounters
	mu        sync.Mutex // serializes admission with shutdown
	started   bool
	closed    atomic.Bool
	cancel    context.CancelFunc
	done      chan struct{}
	jobs      chan *cryptoJob
	slots     chan struct{}
}

type batchKey struct {
	decrypt    bool
	sizeBucket int
}

type cryptoJob struct {
	ctx      context.Context
	key, iv  [32]byte
	dst, src []byte
	decrypt  bool
	queued   time.Time
	done     chan error
}

// NewBatcher creates a scheduler; nil opts disables it entirely.
func NewBatcher(opts *BatchingOptions) *Batcher {
	b := &Batcher{done: make(chan struct{})}
	b.simd, b.available = ige.AES256Available(), ige.AES256Batch4Available()
	if opts == nil {
		return b
	}
	b.enabled, b.opts = true, *opts
	if b.opts.MinBytes <= 0 {
		b.opts.MinBytes = 64 << 10
	}
	if b.opts.MaxPending <= 0 {
		b.opts.MaxPending = 64
	}
	b.opts.MaxPending = max(4, min(b.opts.MaxPending, 1024))
	if b.opts.MaxWait == 0 {
		b.opts.MaxWait = time.Millisecond
	}
	b.opts.MaxWait = max(0, min(b.opts.MaxWait, time.Millisecond))
	b.jobs = make(chan *cryptoJob, b.opts.MaxPending)
	b.slots = make(chan struct{}, b.opts.MaxPending)
	return b
}

// Start starts at most one worker. Unsupported CPUs always take the immediate
// single-message path and do not start a worker.
func (b *Batcher) Start(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started || b.closed.Load() || !b.enabled || !b.available {
		return
	}
	ctx, b.cancel = context.WithCancel(ctx)
	b.started = true
	go b.run(ctx)
}

// Close rejects new work and waits until no worker can access caller buffers.
func (b *Batcher) Close() {
	b.mu.Lock()
	b.closed.Store(true)
	started := b.started
	if b.cancel != nil {
		b.cancel()
	}
	b.mu.Unlock()
	if started {
		<-b.done
	}
}

// Stats returns a concurrent snapshot. The capability flags describe this build
// and CPU; Enabled reports whether the owning client opted in.
func (b *Batcher) Stats() BatchStats {
	if b == nil {
		return BatchStats{}
	}
	s := &b.stats
	return BatchStats{
		Enabled: b.enabled, SIMD: b.simd, BatchSIMD: b.available,
		EncryptBatches: s.encryptBatches.Load(), DecryptBatches: s.decryptBatches.Load(),
		BatchedMessages: s.batchedMessages.Load(), BatchedBytes: s.batchedBytes.Load(),
		SingleMessages: s.singleMessages.Load(), SingleBytes: s.singleBytes.Load(),
		EncryptMessages: s.encryptMessages.Load(), DecryptMessages: s.decryptMessages.Load(),
		EncryptBytes: s.encryptBytes.Load(), DecryptBytes: s.decryptBytes.Load(),
		QueueFull: s.queueFull.Load(), PartialFlushes: s.partialFlushes.Load(),
		Canceled: s.canceled.Load(), QueueWaitNS: s.queueWaitNS.Load(),
		MaxQueueWaitNS: s.maxWaitNS.Load(), Pending: s.pending.Load(),
	}
}

func (b *Batcher) crypt(ctx context.Context, key, iv [32]byte, dst, src []byte, decrypt bool) error {
	if err := ctx.Err(); err != nil {
		b.stats.canceled.Add(1)
		return err
	}
	if b.closed.Load() {
		return ErrBatcherClosed
	}
	if !b.enabled || !b.available || len(src) < b.opts.MinBytes {
		return b.single(ctx, key, iv, dst, src, decrypt)
	}
	b.mu.Lock()
	if b.closed.Load() {
		b.mu.Unlock()
		return ErrBatcherClosed
	}
	if !b.started {
		b.mu.Unlock()
		return b.single(ctx, key, iv, dst, src, decrypt)
	}
	select {
	case b.slots <- struct{}{}:
	default:
		b.mu.Unlock()
		b.stats.queueFull.Add(1)
		return b.single(ctx, key, iv, dst, src, decrypt)
	}
	job := &cryptoJob{
		ctx: ctx, key: key, iv: iv, dst: dst, src: src, decrypt: decrypt,
		queued: time.Now(), done: make(chan error, 1),
	}
	b.stats.pending.Add(1)
	b.jobs <- job // admission token guarantees channel capacity
	b.mu.Unlock()
	// Do not return on ctx.Done: after admission the worker owns these slices.
	// It observes cancellation and acknowledges ownership release through done.
	err := <-job.done
	b.stats.pending.Add(-1)
	<-b.slots
	if err == errRunOnCaller {
		return b.single(ctx, key, iv, dst, src, decrypt)
	}
	return err
}

func (b *Batcher) record(decrypt bool, n int) {
	if decrypt {
		b.stats.decryptMessages.Add(1)
		b.stats.decryptBytes.Add(uint64(n))
	} else {
		b.stats.encryptMessages.Add(1)
		b.stats.encryptBytes.Add(uint64(n))
	}
}

func (b *Batcher) single(ctx context.Context, key, iv [32]byte, dst, src []byte, decrypt bool) error {
	if err := ctx.Err(); err != nil {
		b.stats.canceled.Add(1)
		return err
	}
	c, err := ige.NewAES256(key[:])
	if err != nil {
		return err
	}
	if decrypt {
		c.Decrypt(dst, src, iv[:])
	} else {
		c.Encrypt(dst, src, iv[:])
	}
	b.stats.singleMessages.Add(1)
	b.stats.singleBytes.Add(uint64(len(src)))
	b.record(decrypt, len(src))
	if err := ctx.Err(); err != nil {
		b.stats.canceled.Add(1)
		return err
	}
	return nil
}

func (b *Batcher) waited(job *cryptoJob) {
	n := uint64(time.Since(job.queued))
	b.stats.queueWaitNS.Add(n)
	for old := b.stats.maxWaitNS.Load(); n > old; old = b.stats.maxWaitNS.Load() {
		if b.stats.maxWaitNS.CompareAndSwap(old, n) {
			break
		}
	}
}

func (b *Batcher) execute(jobs []*cryptoJob) {
	active := jobs[:0]
	for _, job := range jobs {
		b.waited(job)
		if err := job.ctx.Err(); err != nil {
			b.stats.canceled.Add(1)
			job.done <- err
		} else {
			active = append(active, job)
		}
	}
	if len(active) != 4 {
		for _, job := range active {
			job.done <- errRunOnCaller
		}
		return
	}
	var keys, ivs [4][32]byte
	var dst, src [4][]byte
	for i, job := range active {
		keys[i], ivs[i], dst[i], src[i] = job.key, job.iv, job.dst, job.src
	}
	c := ige.NewAES256Batch4(keys)
	if active[0].decrypt {
		c.Decrypt(dst, src, ivs)
		b.stats.decryptBatches.Add(1)
	} else {
		c.Encrypt(dst, src, ivs)
		b.stats.encryptBatches.Add(1)
	}
	b.stats.batchedMessages.Add(4)
	for _, job := range active {
		b.stats.batchedBytes.Add(uint64(len(job.src)))
		b.record(job.decrypt, len(job.src))
		err := job.ctx.Err()
		if err != nil {
			b.stats.canceled.Add(1)
		}
		job.done <- err
	}
}

func (b *Batcher) run(ctx context.Context) {
	pending := make(map[batchKey][]*cryptoJob)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	defer close(b.done)
	defer func() {
		b.mu.Lock()
		b.closed.Store(true)
		b.mu.Unlock()
		for _, jobs := range pending {
			for _, job := range jobs {
				b.stats.canceled.Add(1)
				job.done <- ErrBatcherClosed
			}
		}
		for {
			select {
			case job := <-b.jobs:
				b.stats.canceled.Add(1)
				job.done <- ErrBatcherClosed
			default:
				return
			}
		}
	}()
	accept := func(job *cryptoJob) {
		// Server padding and container headers vary. Nearby lengths share the
		// vectorized prefix; the AES batch implementation handles each tail
		// using that lane's saved continuation IV. Never alter wire padding.
		key := batchKey{decrypt: job.decrypt, sizeBucket: (len(job.src) - 1) >> 16}
		pending[key] = append(pending[key], job)
		if len(pending[key]) == 4 {
			jobs := pending[key]
			delete(pending, key)
			b.execute(jobs)
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		// Consume ready jobs before starting a timer. Partial groups flush at
		// their deadline even when traffic is low or message lengths differ.
		draining := true
		for drained := 0; draining && drained < b.opts.MaxPending; drained++ {
			select {
			case <-ctx.Done():
				return
			case job := <-b.jobs:
				accept(job)
			default:
				draining = false
			}
		}
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		var next time.Time
		for key, jobs := range pending {
			deadline := jobs[0].queued.Add(b.opts.MaxWait)
			if !deadline.After(now) {
				delete(pending, key)
				b.stats.partialFlushes.Add(1)
				b.execute(jobs)
			} else if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}
		var wake <-chan time.Time
		if !next.IsZero() {
			timer.Reset(max(0, time.Until(next)))
			wake = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case job := <-b.jobs:
			if wake != nil && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			accept(job)
		case <-wake:
		}
	}
}
