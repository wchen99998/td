package telegram

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/crypto"
	"github.com/gotd/td/mtproto"
	"github.com/gotd/td/pool"
	"github.com/gotd/td/telegram/internal/manager"
	"github.com/gotd/td/tg"
)

type authReusePoolConn struct {
	*idlePoolConn
	invoke InvokeFunc
}

func (c *authReusePoolConn) Invoke(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
	return c.invoke(ctx, input, output)
}

func newAuthReusePoolClient(t *testing.T) *Client {
	t.Helper()
	c := NewClient(1, "hash", Options{DC: 2, NoUpdates: true})
	c.ctx, c.cancel = context.WithCancel(context.Background())
	t.Cleanup(c.cancel)
	primary := pool.Session{DC: 2, AuthKey: crypto.Key{1}.WithID(), Salt: 42}
	c.session.Store(primary)
	c.storeDCSess(c.sessions, primary)
	c.cfg.Store(tg.Config{ThisDC: 2, DCOptions: []tg.DCOption{
		{ID: 2, IPAddress: "127.0.0.1", Port: 443},
		{ID: 2, IPAddress: "127.0.0.2", Port: 443, MediaOnly: true},
		{ID: 3, IPAddress: "127.0.0.3", Port: 443},
	}})
	return c
}

func TestSameDCPoolReusesAuthorization(t *testing.T) {
	for _, media := range []bool{false, true} {
		for _, pfs := range []bool{false, true} {
			t.Run(fmt.Sprintf("media=%v/pfs=%v", media, pfs), func(t *testing.T) {
				c := newAuthReusePoolClient(t)
				c.opts.EnablePFS = pfs
				primary := c.session.Load()
				exports, imports, uploads := 0, 0, 0
				c.tg = tg.NewClient(InvokeFunc(func(context.Context, bin.Encoder, bin.Decoder) error {
					exports++
					return errors.New("unexpected authorization export")
				}))
				c.create = func(_ mtproto.Dialer, mode manager.ConnMode, _ int, opts mtproto.Options, connOpts manager.ConnOptions) pool.Conn {
					require.Equal(t, manager.ConnModeData, mode)
					require.Nil(t, connOpts.Setup)
					require.Equal(t, primary.Salt, opts.Salt)
					if pfs {
						require.True(t, opts.Key.Zero())
						require.Equal(t, primary.AuthKey, opts.PermKey)
					} else {
						require.Equal(t, primary.AuthKey, opts.Key)
					}
					return &authReusePoolConn{idlePoolConn: newIdlePoolConn(), invoke: func(_ context.Context, input bin.Encoder, output bin.Decoder) error {
						switch input.(type) {
						case *tg.UploadSaveBigFilePartRequest:
							uploads++
							output.(*tg.BoolBox).Bool = &tg.BoolTrue{}
							return nil
						default:
							imports++
							return errors.New("unexpected authorization import")
						}
					}}
				}
				var inv CloseInvoker
				var err error
				if media {
					inv, err = c.MediaOnly(c.ctx, 2, 1)
				} else {
					inv, err = c.DC(c.ctx, 2, 1)
				}
				require.NoError(t, err)
				defer inv.Close()
				ok, err := tg.NewClient(inv).UploadSaveBigFilePart(c.ctx, &tg.UploadSaveBigFilePartRequest{FileID: 1, FileTotalParts: 32, Bytes: []byte{1}})
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, 1, uploads)
				require.Zero(t, exports)
				require.Zero(t, imports)
			})
		}
	}
}

func TestSameDCPoolRejectsUnavailableAuthorization(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "different", "wrong-dc", "primary-empty"} {
		for _, media := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/media=%v", kind, media), func(t *testing.T) {
				c := newAuthReusePoolClient(t)
				switch kind {
				case "missing":
					delete(c.sessions, 2)
				case "empty":
					c.sessions[2].Store(pool.Session{DC: 2})
				case "different":
					c.sessions[2].Store(pool.Session{DC: 2, AuthKey: crypto.Key{2}.WithID()})
				case "wrong-dc":
					data := c.session.Load()
					data.DC = 3
					c.sessions[2].Store(data)
				case "primary-empty":
					c.session.Store(pool.Session{DC: 2})
				}
				c.tg = tg.NewClient(InvokeFunc(func(context.Context, bin.Encoder, bin.Decoder) error {
					t.Error("attempted authorization export")
					return errors.New("unexpected export")
				}))
				var inv CloseInvoker
				var err error
				if media {
					inv, err = c.MediaOnly(c.ctx, 2, 1)
				} else {
					inv, err = c.DC(c.ctx, 2, 1)
				}
				require.ErrorContains(t, err, "authorization key")
				require.Nil(t, inv)
			})
		}
	}
}

func TestCrossDCPoolStillTransfersAuthorization(t *testing.T) {
	c := newAuthReusePoolClient(t)
	exports, imports := 0, 0
	c.tg = tg.NewClient(InvokeFunc(func(_ context.Context, input bin.Encoder, output bin.Decoder) error {
		require.Equal(t, &tg.AuthExportAuthorizationRequest{DCID: 3}, input)
		exports++
		*output.(*tg.AuthExportedAuthorization) = tg.AuthExportedAuthorization{ID: 7, Bytes: []byte{8, 9}}
		return nil
	}))
	c.create = func(_ mtproto.Dialer, _ manager.ConnMode, _ int, opts mtproto.Options, connOpts manager.ConnOptions) pool.Conn {
		require.True(t, opts.Key.Zero())
		require.Nil(t, connOpts.Setup, "initial explicit transfer must not be duplicated by setup")
		return &authReusePoolConn{idlePoolConn: newIdlePoolConn(), invoke: func(_ context.Context, input bin.Encoder, output bin.Decoder) error {
			require.Equal(t, &tg.AuthImportAuthorizationRequest{ID: 7, Bytes: []byte{8, 9}}, input)
			imports++
			output.(*tg.AuthAuthorizationBox).Authorization = &tg.AuthAuthorization{User: &tg.User{ID: 7}}
			return nil
		}}
	}
	inv, err := c.DC(c.ctx, 3, 1)
	require.NoError(t, err)
	defer inv.Close()
	require.Equal(t, 1, exports)
	require.Equal(t, 1, imports)
}

func TestSameDCPoolPFSResetFollowsCurrentPrimary(t *testing.T) {
	for _, media := range []bool{false, true} {
		for _, migrated := range []bool{false, true} {
			t.Run(fmt.Sprintf("media=%v/migrated=%v", media, migrated), func(t *testing.T) {
				c := newAuthReusePoolClient(t)
				c.opts.EnablePFS = true
				deadCalls := 0
				c.onDead = func(err error) {
					require.ErrorIs(t, err, mtproto.ErrPFSDropKeysRequired)
					deadCalls++
				}
				var onDead func(error)
				c.create = func(_ mtproto.Dialer, _ manager.ConnMode, _ int, _ mtproto.Options, opts manager.ConnOptions) pool.Conn {
					onDead = opts.OnDead
					return newIdlePoolConn()
				}
				var inv CloseInvoker
				var err error
				if media {
					inv, err = c.MediaOnly(c.ctx, 2, 1)
				} else {
					inv, err = c.DC(c.ctx, 2, 1)
				}
				require.NoError(t, err)
				defer inv.Close()
				require.NoError(t, inv.Invoke(c.ctx, &tg.UploadSaveBigFilePartRequest{}, &tg.BoolBox{}))
				require.NotNil(t, onDead)
				if migrated {
					// The pool still belongs to DC 2 after the primary moves.
					c.session.Store(pool.Session{DC: 3, AuthKey: crypto.Key{3}.WithID(), Salt: 43})
				}
				primaryBefore := c.session.Load()
				onDead(mtproto.ErrPFSDropKeysRequired)
				require.Equal(t, 1, deadCalls)
				cached := c.sessions[2].Load()
				require.True(t, cached.AuthKey.Zero())
				require.Zero(t, cached.Salt)
				if migrated {
					require.Equal(t, primaryBefore, c.session.Load(), "must not clear a different primary DC")
				} else {
					primary := c.session.Load()
					require.True(t, primary.AuthKey.Zero())
					require.Zero(t, primary.Salt)
				}
			})
		}
	}
}
