// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	cryptorand "crypto/rand"
	"errors"
	"hash"
	"io"
	mathrand "math/rand/v2"
	"sync/atomic"

	"github.com/refraction-networking/utls/internal/tls13"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

// keyCache is a lock-free cache pool for pre-generated ECDHE keys
type keyCache struct {
	keys []*ecdh.PrivateKey
	// Using atomic for lock-free random access
	initialized atomic.Bool
}

const keyCacheSize = 100

// Global key cache pools for each curve type
var (
	keyCacheX25519 = &keyCache{}
	keyCacheP256   = &keyCache{}
	keyCacheP384   = &keyCache{}
	keyCacheP521   = &keyCache{}
)

// initKeyCache initializes the key cache for a specific curve
func (kc *keyCache) init(curve ecdh.Curve) {
	if kc.initialized.Load() {
		return
	}

	keys := make([]*ecdh.PrivateKey, keyCacheSize)
	for i := 0; i < keyCacheSize; i++ {
		key, err := curve.GenerateKey(cryptorand.Reader)
		if err != nil {
			// Fallback: continue with fewer keys if generation fails
			continue
		}
		keys[i] = key
	}
	kc.keys = keys
	kc.initialized.Store(true)
}

// getRandomKey returns a random key from the cache
func (kc *keyCache) getRandomKey() *ecdh.PrivateKey {
	if !kc.initialized.Load() || len(kc.keys) == 0 {
		return nil
	}
	// Lock-free random selection using math/rand/v2
	idx := mathrand.IntN(len(kc.keys))
	return kc.keys[idx]
}

// getCacheForCurveID returns the appropriate key cache for a curve ID
func getCacheForCurveID(curveID CurveID) *keyCache {
	switch curveID {
	case X25519:
		return keyCacheX25519
	case CurveP256:
		return keyCacheP256
	case CurveP384:
		return keyCacheP384
	case CurveP521:
		return keyCacheP521
	default:
		return nil
	}
}

// InitAllKeyCaches pre-initializes all key caches for all supported curves.
// This should be called during application startup for best performance.
func InitAllKeyCaches() {
	keyCacheX25519.init(ecdh.X25519())
	keyCacheP256.init(ecdh.P256())
	keyCacheP384.init(ecdh.P384())
	keyCacheP521.init(ecdh.P521())
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return tls13.ExpandLabel(c.hash.New, trafficSecret, "traffic upd", nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = tls13.ExpandLabel(c.hash.New, trafficSecret, "key", nil, c.keyLen)
	iv = tls13.ExpandLabel(c.hash.New, trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := tls13.ExpandLabel(c.hash.New, baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(s *tls13.MasterSecret, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := s.ExporterMasterSecret(transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		return expMasterSecret.Exporter(label, context, length), nil
	}
}

type keySharePrivateKeys struct {
	curveID    CurveID
	ecdhe      *ecdh.PrivateKey
	mlkem      *mlkem.DecapsulationKey768
	mlkemEcdhe *ecdh.PrivateKey // [uTLS] seperate ecdhe key for pq keyshare in line with Chrome, instead of reusing ecdhe key like stdlib
}

const x25519PublicKeySize = 32

// generateECDHEKey returns a PrivateKey that implements Diffie-Hellman
// according to RFC 8446, Section 4.2.8.2.
// It uses a pre-generated key cache for high performance.
func generateECDHEKey(rand io.Reader, curveID CurveID) (*ecdh.PrivateKey, error) {
	// Try to get a key from the cache first
	cache := getCacheForCurveID(curveID)
	if cache != nil {
		// Lazy initialization: initialize cache on first use if not already done
		if !cache.initialized.Load() {
			curve, ok := curveForCurveID(curveID)
			if ok {
				cache.init(curve)
			}
		}

		// Get a random key from the cache
		if key := cache.getRandomKey(); key != nil {
			return key, nil
		}
	}

	// Fallback: generate a new key if cache is not available or empty
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	return curve.GenerateKey(rand)
}

func curveForCurveID(id CurveID) (ecdh.Curve, bool) {
	switch id {
	case X25519:
		return ecdh.X25519(), true
	case CurveP256:
		return ecdh.P256(), true
	case CurveP384:
		return ecdh.P384(), true
	case CurveP521:
		return ecdh.P521(), true
	default:
		return nil, false
	}
}

func curveIDForCurve(curve ecdh.Curve) (CurveID, bool) {
	switch curve {
	case ecdh.X25519():
		return X25519, true
	case ecdh.P256():
		return CurveP256, true
	case ecdh.P384():
		return CurveP384, true
	case ecdh.P521():
		return CurveP521, true
	default:
		return 0, false
	}
}
