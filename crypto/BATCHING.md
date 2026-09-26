# Optional AES-IGE batching

`telegram.Options.CryptoBatching = &telegram.CryptoBatchingOptions{}` enables
the raw-key AES-256 implementation and batches four independent MTProto messages
when their direction matches and their padded lengths lie in the same 64 KiB
size bucket. Each lane keeps its own continuation IV for any unequal tail.
Leave the option nil to use the
original `crypto/aes` plus `ige.EncryptBlocks`/`DecryptBlocks` implementation. This
allows comparisons without changing the application or the wire protocol.

The SIMD build requires Go 1.26 and `GOEXPERIMENT=simd`. Runtime checks select the
single-message AVX/AES implementation and the four-message AVX-512/VAES
implementation separately. Unsupported builds/CPUs, `purego`, BoringCrypto and
FIPS mode use the ordinary Go AES implementation. This does not make MTProto or
IGE a FIPS-approved protocol.

One scheduler belongs to each Telegram client and is shared by its primary,
upload, media and CDN pool connections. Construction starts no goroutine.
`Client.Run` starts the worker and closes it on exit. The scheduler only performs
CPU work; each original caller retains its connection, exchange lock, transport
write and RPC retry behavior.

Defaults are a 64 KiB minimum padded size, at most 64 queued or worker-executed
messages, and a
one-millisecond intentional collection window. Already-ready jobs are consumed
first. Smaller messages, unsupported hardware and a full queue use the optimized
single-message path immediately. Partial batches return ownership to their
original callers, which process them individually in parallel without adding
goroutines. These caller-owned fallbacks are outside the pending bound. Negative
`MaxWait` disables deliberate collection waits; positive values are capped at
one millisecond. Scheduler/CPU contention may make observed queue time longer
than this collection budget.

Cancellation does not allow a caller to reuse a queued buffer until the worker
has acknowledged release. Shutdown rejects new work and drains pending jobs.
Encryption still generates independent random padding and message keys on each
attempt. Decryption still verifies every message key, decoded length, padding,
session and replay condition. Containers remain one outer IGE chain.

`Client.CryptoStats()` exposes capabilities, actual single/batched work, byte
counts by direction, queue saturation, partial flushes, cancellations and queue
wait totals/maxima. These counters measure local cryptography, including retried
or subsequently rejected messages; they are not successful network byte counts.
The nil-option legacy path does not increment optimized-path counters. Measure
the batched-message fraction and queue wait on real traffic before interpreting
kernel benchmark gains as application throughput gains.

Low-level callers can use `crypto.NewBatcher`, `Start`, `Close`, and
`Cipher.WithBatcher`. Context-aware cipher methods wait for buffer ownership to
be released even after cancellation. Passing nil or a disabled batcher to
`WithBatcher` restores the legacy cipher path.
