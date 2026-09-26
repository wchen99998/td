package crypto

import (
	"context"
	"crypto/aes"
	"io"

	"github.com/gotd/ige"

	"github.com/gotd/td/bin"
)

func countPadding(l int) int { return 16 + (16 - (l % 16)) }

// encryptMessage encrypts plaintext using AES-IGE.
func (c Cipher) encryptMessage(k AuthKey, plaintext *bin.Buffer) (EncryptedMessage, error) {
	return c.encryptMessageContext(context.Background(), k, plaintext)
}

func (c Cipher) encryptMessageContext(ctx context.Context, k AuthKey, plaintext *bin.Buffer) (EncryptedMessage, error) {
	if err := ctx.Err(); err != nil {
		return EncryptedMessage{}, err
	}
	offset := len(plaintext.Buf)
	plaintext.Buf = append(plaintext.Buf, make([]byte, countPadding(offset))...)
	if _, err := io.ReadFull(c.rand, plaintext.Buf[offset:]); err != nil {
		return EncryptedMessage{}, err
	}

	messageKey := MessageKey(k.Value, plaintext.Buf, c.encryptSide)
	key, iv := Keys(k.Value, messageKey, c.encryptSide)
	msg := EncryptedMessage{
		AuthKeyID:     k.ID,
		MsgKey:        messageKey,
		EncryptedData: make([]byte, len(plaintext.Buf)),
	}
	if c.batcher != nil {
		if err := c.batcher.crypt(ctx, key, iv, msg.EncryptedData, plaintext.Buf, false); err != nil {
			return EncryptedMessage{}, err
		}
	} else {
		aesBlock, err := aes.NewCipher(key[:])
		if err != nil {
			return EncryptedMessage{}, err
		}
		ige.EncryptBlocks(aesBlock, iv[:], msg.EncryptedData, plaintext.Buf)
	}
	return msg, nil
}

// Encrypt encrypts EncryptedMessageData using AES-IGE to given buffer.
func (c Cipher) Encrypt(key AuthKey, data EncryptedMessageData, b *bin.Buffer) error {
	return c.EncryptContext(context.Background(), key, data, b)
}

// EncryptContext is Encrypt with cancellation-aware crypto scheduling.
// It never returns while a scheduler still owns b or data's backing buffers.
func (c Cipher) EncryptContext(ctx context.Context, key AuthKey, data EncryptedMessageData, b *bin.Buffer) error {
	b.Reset()
	if err := data.EncodeWithoutCopy(b); err != nil {
		return err
	}
	if c.batcher != nil {
		return c.encryptBufferContext(ctx, key, b)
	}

	msg, err := c.encryptMessageContext(ctx, key, b)
	if err != nil {
		return err
	}

	b.Reset()
	if err := msg.Encode(b); err != nil {
		return err
	}

	return nil
}

// encryptBufferContext encrypts an encoded plaintext buffer in place. Keeping
// plaintext at offset zero preserves custom encoders and input slices that
// overlap b. The final shift replaces the existing ciphertext copy without
// allocating a second full-size buffer.
func (c Cipher) encryptBufferContext(ctx context.Context, k AuthKey, b *bin.Buffer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	offset := len(b.Buf)
	b.Expand(countPadding(offset))
	if _, err := io.ReadFull(c.rand, b.Buf[offset:]); err != nil {
		return err
	}

	messageKey := MessageKey(k.Value, b.Buf, c.encryptSide)
	key, iv := Keys(k.Value, messageKey, c.encryptSide)
	if err := c.batcher.crypt(ctx, key, iv, b.Buf, b.Buf, false); err != nil {
		return err
	}

	const headerSize = 8 + 16 // auth_key_id and msg_key
	n := len(b.Buf)
	b.Expand(headerSize)
	copy(b.Buf[headerSize:], b.Buf[:n])
	copy(b.Buf[:8], k.ID[:])
	copy(b.Buf[8:headerSize], messageKey[:])
	return nil
}
