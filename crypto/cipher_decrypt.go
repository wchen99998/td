package crypto

import (
	"context"
	"crypto/aes"

	"github.com/go-faster/errors"

	"github.com/gotd/ige"

	"github.com/gotd/td/bin"
)

// DecryptFromBuffer decodes EncryptedMessage and decrypts it.
func (c Cipher) DecryptFromBuffer(k AuthKey, buf *bin.Buffer) (*EncryptedMessageData, error) {
	return c.DecryptFromBufferContext(context.Background(), k, buf)
}

// DecryptFromBufferContext is DecryptFromBuffer with cancellation-aware crypto
// scheduling. All message-key, plaintext and padding checks remain mandatory.
func (c Cipher) DecryptFromBufferContext(ctx context.Context, k AuthKey, buf *bin.Buffer) (*EncryptedMessageData, error) {
	msg := &EncryptedMessage{}
	// Because we assume that buffer is valid during decrypting, we able to
	// use DecodeWithoutCopy and do not allocate inner buffer for EncryptedMessage.
	if err := msg.DecodeWithoutCopy(buf); err != nil {
		return nil, err
	}

	return c.DecryptContext(ctx, k, msg)
}

// Decrypt decrypts data from encrypted message using AES-IGE.
func (c Cipher) Decrypt(k AuthKey, encrypted *EncryptedMessage) (*EncryptedMessageData, error) {
	return c.DecryptContext(context.Background(), k, encrypted)
}

// DecryptContext is Decrypt with cancellation-aware crypto scheduling.
func (c Cipher) DecryptContext(ctx context.Context, k AuthKey, encrypted *EncryptedMessage) (*EncryptedMessageData, error) {
	plaintext, err := c.decryptMessageContext(ctx, k, encrypted)
	if err != nil {
		return nil, err
	}

	side := c.encryptSide.DecryptSide()
	// Checking SHA256 hash value of msg_key
	msgKey := MessageKey(k.Value, plaintext, side)
	if msgKey != encrypted.MsgKey {
		return nil, errors.New("msg_key is invalid")
	}

	msg := &EncryptedMessageData{}
	// Notice: do not re-use plaintext, because we use DecodeWithoutCopy, it references
	// original buffer.
	if err := msg.DecodeWithoutCopy(&bin.Buffer{Buf: plaintext}); err != nil {
		return nil, err
	}

	{
		// Checking that padding of decrypted message is not too big.
		const maxPadding = 1024
		n := int(msg.MessageDataLen)
		paddingLen := len(msg.MessageDataWithPadding) - n

		switch {
		case n < 0:
			return nil, errors.Errorf("message length is invalid: %d less than zero", n)
		case n%4 != 0:
			return nil, errors.Errorf("message length is invalid: %d is not divisible by 4", n)
		case paddingLen > maxPadding:
			return nil, errors.Errorf("padding %d of message is too big", paddingLen)
		}
	}

	return msg, nil
}

// decryptMessage decrypts data from encrypted message using AES-IGE.
func (c Cipher) decryptMessage(k AuthKey, encrypted *EncryptedMessage) ([]byte, error) {
	return c.decryptMessageContext(context.Background(), k, encrypted)
}

func (c Cipher) decryptMessageContext(ctx context.Context, k AuthKey, encrypted *EncryptedMessage) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.ID != encrypted.AuthKeyID {
		return nil, errors.New("unknown auth key id")
	}
	if len(encrypted.EncryptedData)%16 != 0 {
		return nil, errors.New("invalid encrypted data padding")
	}

	key, iv := Keys(k.Value, encrypted.MsgKey, c.encryptSide.DecryptSide())
	plaintext := make([]byte, len(encrypted.EncryptedData))
	if c.batcher != nil {
		if err := c.batcher.crypt(ctx, key, iv, plaintext, encrypted.EncryptedData, true); err != nil {
			return nil, err
		}
	} else {
		cipher, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		ige.DecryptBlocks(cipher, iv[:], plaintext, encrypted.EncryptedData)
	}

	return plaintext, nil
}
