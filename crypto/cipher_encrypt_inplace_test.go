package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/testutil"
)

type packetEncoder func(*bin.Buffer) error

func (f packetEncoder) Encode(b *bin.Buffer) error { return f(b) }

func TestInPlaceEncryptMatchesLegacy(t *testing.T) {
	for _, side := range []Side{Client, Server} {
		for _, size := range []int{0, 4, 12, 16, 32, 4096, 512 << 10} {
			for _, encoded := range []bool{false, true} {
				t.Run(fmt.Sprintf("side%d/size%d/encoder%t", side, size, encoded), func(t *testing.T) {
					payload := bytes.Repeat([]byte{43}, size)
					data := EncryptedMessageData{Salt: 17, SessionID: 23, MessageID: 29, SeqNo: 3, MessageDataLen: int32(size), MessageDataWithPadding: payload}
					if encoded {
						data.Message = packetEncoder(func(b *bin.Buffer) error { b.Put(payload); return nil })
					}
					for _, capacity := range []int{0, size + 64, size + 128} {
						legacy := Cipher{rand: testutil.Rand([]byte("padding")), encryptSide: side}
						optimized := Cipher{rand: testutil.Rand([]byte("padding")), encryptSide: side}.WithBatcher(NewBatcher(&BatchingOptions{}))
						want, got := bin.Buffer{Buf: make([]byte, 0, capacity)}, bin.Buffer{Buf: make([]byte, 0, capacity)}
						for range 2 { // Exercise reuse and advancing padding randomness.
							require.NoError(t, legacy.Encrypt(testAuthKey, data, &want))
							require.NoError(t, optimized.Encrypt(testAuthKey, data, &got))
							require.Equal(t, want.Buf, got.Buf)
						}
						require.Equal(t, bytes.Repeat([]byte{43}, size), payload)
					}
				})
			}
		}
	}
}

func TestInPlaceEncryptPreservesAliasedInputAndEncoderPrefix(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		t.Run(fmt.Sprintf("encoder%t", encoded), func(t *testing.T) {
			var packets [2][]byte
			for i := range packets {
				b := bin.Buffer{Buf: make([]byte, 32+4096, 32+4096+128)}
				for j := range b.Buf {
					b.Buf[j] = byte(j*31 + 1)
				}
				payload := b.Buf[32:]
				data := EncryptedMessageData{Salt: 17, SessionID: 23, MessageID: 29, SeqNo: 3, MessageDataLen: int32(len(payload)), MessageDataWithPadding: payload}
				if encoded {
					var prefix bin.Buffer
					header := data
					header.MessageDataWithPadding, header.MessageDataLen = nil, 0
					require.NoError(t, header.Encode(&prefix))
					data.Message = packetEncoder(func(out *bin.Buffer) error {
						// Existing encoders see the initialized inner header at offset zero.
						require.Equal(t, prefix.Buf, out.Buf)
						out.Put(payload)
						return nil
					})
				}
				c := NewClientCipher(testutil.Rand([]byte("padding")))
				if i == 1 {
					c = c.WithBatcher(NewBatcher(&BatchingOptions{}))
				}
				require.NoError(t, c.Encrypt(testAuthKey, data, &b))
				packets[i] = b.Buf
			}
			require.Equal(t, packets[0], packets[1])
		})
	}
}

func TestInPlaceEncryptErrorBehavior(t *testing.T) {
	encodeErr := errors.New("encoder failed")
	for _, failure := range []string{"encode", "padding", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			var output [2][]byte
			var failures [2]error
			for i := range output {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				data := EncryptedMessageData{Message: packetEncoder(func(b *bin.Buffer) error {
					b.Put([]byte{1, 2, 3, 4})
					if failure == "encode" {
						return encodeErr
					}
					return nil
				})}
				var random io.Reader = testutil.ZeroRand{}
				if failure == "padding" {
					random = bytes.NewReader([]byte{7, 8, 9})
				}
				if failure == "cancel" {
					cancel()
				}
				c := NewClientCipher(random)
				if i == 1 {
					c = c.WithBatcher(NewBatcher(&BatchingOptions{}))
				}
				b := bin.Buffer{Buf: make([]byte, 128)}
				failures[i] = c.EncryptContext(ctx, testAuthKey, data, &b)
				output[i] = b.Buf
			}
			require.EqualError(t, failures[1], failures[0].Error())
			require.Equal(t, output[0], output[1])
		})
	}
}

func TestInPlaceEncryptQueuedCancellation(t *testing.T) {
	b, start := heldBatcher(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewClientCipher(testutil.ZeroRand{}).WithBatcher(b)
	var wire bin.Buffer
	data := EncryptedMessageData{MessageDataLen: 4096, MessageDataWithPadding: make([]byte, 4096)}
	done := make(chan error, 1)
	go func() { done <- c.EncryptContext(ctx, testAuthKey, data, &wire) }()
	waitPending(t, b, 1)
	cancel()
	select {
	case <-done:
		t.Fatal("encryption released a buffer still owned by the worker")
	default:
	}
	start()
	require.ErrorIs(t, result(t, done), context.Canceled)
	// A race here would mean the worker accessed memory after acknowledging it.
	for i := range wire.Buf {
		wire.Buf[i] = 0xa5
	}
	b.Close()
}

func TestInPlaceEncryptBatchMatchesLegacy(t *testing.T) {
	b, start := heldBatcher(t, 4)
	var wires [4]bin.Buffer
	var expected [4]bin.Buffer
	var done [4]chan error
	for i := range wires {
		data := EncryptedMessageData{SessionID: int64(i + 1), MessageDataLen: int32(4096 + i*16), MessageDataWithPadding: bytes.Repeat([]byte{byte(i + 1)}, 4096+i*16)}
		require.NoError(t, NewClientCipher(testutil.ZeroRand{}).Encrypt(testAuthKey, data, &expected[i]))
		done[i] = make(chan error, 1)
		go func() {
			done[i] <- NewClientCipher(testutil.ZeroRand{}).WithBatcher(b).Encrypt(testAuthKey, data, &wires[i])
		}()
	}
	waitPending(t, b, 4)
	start()
	for i := range wires {
		require.NoError(t, result(t, done[i]))
		require.Equal(t, expected[i].Buf, wires[i].Buf)
	}
	require.EqualValues(t, 4, b.Stats().BatchedMessages)
}

func TestInPlaceEncryptAndDecryptBufferLifetimes(t *testing.T) {
	c := NewClientCipher(testutil.ZeroRand{}).WithBatcher(NewBatcher(&BatchingOptions{}))
	s := NewServerCipher(testutil.ZeroRand{}).WithBatcher(NewBatcher(&BatchingOptions{}))
	payload := bytes.Repeat([]byte{7}, 4096)
	data := EncryptedMessageData{MessageDataLen: int32(len(payload)), MessageDataWithPadding: payload}
	var first, second bin.Buffer
	require.NoError(t, c.Encrypt(testAuthKey, data, &first))
	ciphertext := bytes.Clone(first.Buf)
	decoded, err := s.DecryptFromBuffer(testAuthKey, &bin.Buffer{Buf: first.Buf})
	require.NoError(t, err)
	require.NoError(t, c.Encrypt(testAuthKey, data, &second))
	require.Equal(t, ciphertext, first.Buf)
	clear(first.Buf) // Simulate returning the transport buffer to its pool.
	clear(second.Buf)
	require.Equal(t, payload, decoded.Data())
}
