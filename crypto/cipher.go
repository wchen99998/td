package crypto

import "io"

// Cipher is message encryption utility struct.
type Cipher struct {
	rand        io.Reader
	encryptSide Side
	batcher     *Batcher
}

// WithBatcher shares an explicitly managed scheduler with other ciphers.
// The caller owns Start and Close. A nil or disabled scheduler preserves the
// original AES-IGE implementation.
func (c Cipher) WithBatcher(b *Batcher) Cipher {
	c.batcher = nil
	if b != nil && b.enabled {
		c.batcher = b
	}
	return c
}

// Rand returns random generator.
func (c Cipher) Rand() io.Reader {
	return c.rand
}

// NewClientCipher creates new client-side Cipher.
func NewClientCipher(rand io.Reader) Cipher {
	return Cipher{rand: rand, encryptSide: Client}
}

// NewServerCipher creates new server-side Cipher.
func NewServerCipher(rand io.Reader) Cipher {
	return Cipher{rand: rand, encryptSide: Server}
}
