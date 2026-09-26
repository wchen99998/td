package mtproto

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/crypto"
	"github.com/gotd/td/testutil"
)

type recordingContextCipher struct {
	crypto.Cipher
	encryptContext, decryptContext context.Context
}

func (c *recordingContextCipher) EncryptContext(ctx context.Context, _ crypto.AuthKey, _ crypto.EncryptedMessageData, _ *bin.Buffer) error {
	c.encryptContext = ctx
	return ctx.Err()
}

func (c *recordingContextCipher) DecryptFromBufferContext(ctx context.Context, _ crypto.AuthKey, _ *bin.Buffer) (*crypto.EncryptedMessageData, error) {
	c.decryptContext = ctx
	return nil, ctx.Err()
}

func TestConnectionPassesCancellationToCipher(t *testing.T) {
	cipher := &recordingContextCipher{Cipher: crypto.NewClientCipher(testutil.ZeroRand{})}
	c := New(nil, Options{Cipher: cipher})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.write(ctx, 1, 1, testPayload{Data: []byte{1, 2, 3, 4}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write: %v", err)
	}
	if cipher.encryptContext != ctx {
		t.Fatal("write lost request context")
	}
	if _, err := c.decryptMessageContext(ctx, &bin.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("read: %v", err)
	}
	if cipher.decryptContext != ctx {
		t.Fatal("read lost connection context")
	}
}

type legacyOnlyCipher struct{ calls int }

var errLegacyCipher = errors.New("legacy test cipher")

func (c *legacyOnlyCipher) Encrypt(crypto.AuthKey, crypto.EncryptedMessageData, *bin.Buffer) error {
	c.calls++
	return errLegacyCipher
}

func (c *legacyOnlyCipher) DecryptFromBuffer(crypto.AuthKey, *bin.Buffer) (*crypto.EncryptedMessageData, error) {
	c.calls++
	return nil, errLegacyCipher
}

func TestConnectionPreservesCustomLegacyCipher(t *testing.T) {
	cipher := &legacyOnlyCipher{}
	c := New(nil, Options{Cipher: cipher})
	ctx := context.Background()
	if err := c.write(ctx, 1, 1, testPayload{Data: []byte{1, 2, 3, 4}}); !errors.Is(err, errLegacyCipher) {
		t.Fatalf("write: %v", err)
	}
	if _, err := c.decryptMessageContext(ctx, &bin.Buffer{}); !errors.Is(err, errLegacyCipher) {
		t.Fatalf("read: %v", err)
	}
	if cipher.calls != 2 {
		t.Fatalf("legacy cipher calls=%d", cipher.calls)
	}
}
