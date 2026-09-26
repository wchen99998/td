package telegram

import "github.com/gotd/td/crypto"

// CryptoBatchingOptions controls explicitly enabled local AES-IGE batching.
type CryptoBatchingOptions = crypto.BatchingOptions

// CryptoStats reports cryptographic work across all connections of a Client.
// These counters measure CPU processing, not successfully transferred bytes.
type CryptoStats = crypto.BatchStats

// CryptoStats returns a concurrent snapshot of this client's crypto counters.
func (c *Client) CryptoStats() CryptoStats {
	return c.cryptoBatcher.Stats()
}
