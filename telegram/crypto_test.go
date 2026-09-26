package telegram

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/pool"
	"github.com/gotd/td/telegram/internal/manager"
	"github.com/gotd/td/testutil"
)

func TestClientSharesCryptoAcrossPoolConnections(t *testing.T) {
	c := NewClient(1, "hash", Options{CryptoBatching: &CryptoBatchingOptions{}, Random: testutil.ZeroRand{}})
	var ciphers []mtproto.Cipher
	c.create = func(_ mtproto.Dialer, _ manager.ConnMode, _ int, opts mtproto.Options, _ manager.ConnOptions) pool.Conn {
		ciphers = append(ciphers, opts.Cipher)
		return nil
	}
	c.createConn(1, manager.ConnModeData, nil, nil)
	c.createConn(2, manager.ConnModeData, nil, nil)
	data := crypto.EncryptedMessageData{MessageDataLen: 4, MessageDataWithPadding: []byte{1, 2, 3, 4}}
	for _, cipher := range ciphers {
		if err := cipher.Encrypt(crypto.Key{1}.WithID(), data, &bin.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	if s := c.CryptoStats(); !s.Enabled || s.SingleMessages != 2 || s.EncryptMessages != 2 {
		t.Fatalf("pool connections did not share counters: %+v", s)
	}
}

func TestClientCryptoOptOutUsesLegacy(t *testing.T) {
	c := NewClient(1, "hash", Options{Random: testutil.ZeroRand{}})
	data := crypto.EncryptedMessageData{MessageDataLen: 4, MessageDataWithPadding: []byte{1, 2, 3, 4}}
	if err := c.opts.Cipher.Encrypt(crypto.Key{1}.WithID(), data, &bin.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if s := c.CryptoStats(); s.Enabled || s.SingleMessages != 0 || s.BatchedMessages != 0 {
		t.Fatalf("opt-out entered optimized path: %+v", s)
	}
}

func TestClientRunClosesCryptoScheduler(t *testing.T) {
	c := NewClient(1, "hash", Options{NoUpdates: true, CryptoBatching: &CryptoBatchingOptions{}})
	c.conn = runClientConn{run: func(ctx context.Context) error {
		c.onReady()
		<-ctx.Done()
		return ctx.Err()
	}}
	data := crypto.EncryptedMessageData{MessageDataLen: 4, MessageDataWithPadding: []byte{1, 2, 3, 4}}
	if err := c.Run(context.Background(), func(ctx context.Context) error {
		return c.opts.Cipher.(mtproto.ContextCipher).EncryptContext(ctx, crypto.Key{1}.WithID(), data, &bin.Buffer{})
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.opts.Cipher.Encrypt(crypto.Key{1}.WithID(), data, &bin.Buffer{}); !errors.Is(err, crypto.ErrBatcherClosed) {
		t.Fatalf("scheduler survived client shutdown: %v", err)
	}
	if c.CryptoStats().Pending != 0 {
		t.Fatal("client shutdown retained queued buffers")
	}
}
