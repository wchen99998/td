# Optional AES-IGE batching

`telegram.Options.CryptoBatching = &telegram.CryptoBatchingOptions{}` enables
the raw-key AES-256 implementation and batches four independent MTProto messages
when their direction matches and their padded lengths lie in the same 64 KiB
size bucket. Each lane keeps its own continuation IV for any unequal tail.
Leave the option nil to use the
original `crypto/aes` plus `ige.EncryptBlocks`/`DecryptBlocks` implementation. This
allows comparisons without changing the application or the wire protocol.

Set `SingleMessageOnly: true` in these options to use accelerated single-message
AES without a worker, queue allocation or collection wait. This is appropriate
for network-paced traffic where four prepared packets rarely arrive together.
`MaxWait < 0` still uses a queue to batch jobs that are already ready; it is a
different policy. `CryptoStats.BatchingEnabled` reports the selected, supported
batching policy separately from the `BatchSIMD` hardware/build capability.

The enabled encryption path uses its plaintext buffer in place and then moves
the ciphertext to make room for the outer header. This avoids a temporary
packet-sized ciphertext allocation while retaining custom-encoder behavior and
overlapping input semantics. Decrypted payloads still own independent memory.

The SIMD build requires Go 1.26 and `GOEXPERIMENT=simd`. Runtime checks select the
single-message AVX/AES implementation and the four-message AVX-512/VAES
implementation separately. Unsupported builds/CPUs, `purego`, BoringCrypto and
FIPS mode use the ordinary Go AES implementation. This does not make MTProto or
IGE a FIPS-approved protocol.

Applications must replace **both** modules in their own `go.mod`: dependency
modules' `replace` directives are not inherited. These commands resolve the TD
branch once and record an immutable pseudo-version alongside the matching IGE
version:

```sh
td_fork_version="$(go list -m -f '{{.Version}}' github.com/wchen99998/td@codex/aes-ige-simd)"
go mod edit "-replace=github.com/gotd/td=github.com/wchen99998/td@${td_fork_version}"
go mod edit -replace=github.com/gotd/ige=github.com/wchen99998/ige@v0.0.0-20260926043934-f3b4f4ad152c
go mod tidy
```

Keep imports under `github.com/gotd/td` and `github.com/gotd/ige`, and commit the
resulting `go.mod` and `go.sum`. Replacing only TD leaves the upstream IGE module
without the new AES-256 APIs and fails to compile.

One scheduler belongs to each Telegram client and is shared by its primary,
upload, media and CDN pool connections. Construction starts no goroutine.
`Client.Run` starts the worker and closes it on exit. The scheduler only performs
CPU work; each original caller retains its connection, exchange lock, transport
write and RPC retry behavior.

Defaults are a 64 KiB minimum padded size, at most 64 queued or worker-executed
messages, and a
two-millisecond intentional collection window. Already-ready jobs are consumed
first. Smaller messages, unsupported hardware and a full queue use the optimized
single-message path immediately. Partial batches return ownership to their
original callers, which process them individually in parallel without adding
goroutines. These caller-owned fallbacks are outside the pending bound. Negative
`MaxWait` disables deliberate collection waits; positive values are capped at
two milliseconds. Scheduler/CPU contention may make observed queue time longer
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
