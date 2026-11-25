package util

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// Algorithms of the VSatellite edge encryption keys returned by GET /v1/edgeencryptionkeys/{dekHash}.
const (
	EdgeKeyAlgorithmED25519  = "ED25519"
	EdgeKeyAlgorithmVSatHPKE = "VSAT_HPKE"
)

const (
	ed25519EdgeKeySize = 32 // X25519 public key used with a NaCl sealed box
	p384EdgeKeySize    = 97 // uncompressed P-384 point: 0x04 || X || Y
)

// EncryptForEdgeKey encrypts plaintext so that only the VSatellite that owns an edge encryption key
// can decrypt it, for example the key password of a service generated private key. It returns the
// base64 value the platform expects. keyB64 is the base64 public key, keyAlgorithm and companyID come
// from the same edge encryption key response.
//
// It follows the platform UI:
//   - ED25519 (or no algorithm, from older responses): NaCl sealed box with the 32-byte key.
//   - VSAT_HPKE: HPKE (RFC 9180) with DHKEM(P-384, HKDF-SHA384), HKDF-SHA512 and AES-256-GCM, using
//     companyID as both info and additional data; the result is enc || ciphertext.
func EncryptForEdgeKey(plaintext []byte, keyB64, keyAlgorithm, companyID string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode the VSatellite encryption key: %w", err)
	}

	switch keyAlgorithm {
	case EdgeKeyAlgorithmED25519, "":
		if len(key) != ed25519EdgeKeySize {
			return "", fmt.Errorf("VSatellite encryption key has %d bytes, %s needs %d", len(key), EdgeKeyAlgorithmED25519, ed25519EdgeKeySize)
		}
		var publicKey [ed25519EdgeKeySize]byte
		copy(publicKey[:], key)
		sealed, err := box.SealAnonymous(nil, plaintext, &publicKey, rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt for the VSatellite: %w", err)
		}
		return base64.StdEncoding.EncodeToString(sealed), nil

	case EdgeKeyAlgorithmVSatHPKE:
		if len(key) != p384EdgeKeySize {
			return "", fmt.Errorf("VSatellite encryption key has %d bytes, %s needs %d", len(key), EdgeKeyAlgorithmVSatHPKE, p384EdgeKeySize)
		}
		if companyID == "" {
			return "", fmt.Errorf("VSatellite encryption key has no company ID, which %s needs", EdgeKeyAlgorithmVSatHPKE)
		}
		ecdhKey, err := ecdh.P384().NewPublicKey(key)
		if err != nil {
			return "", fmt.Errorf("invalid %s VSatellite encryption key: %w", EdgeKeyAlgorithmVSatHPKE, err)
		}
		publicKey, err := hpke.NewDHKEMPublicKey(ecdhKey)
		if err != nil {
			return "", fmt.Errorf("invalid %s VSatellite encryption key: %w", EdgeKeyAlgorithmVSatHPKE, err)
		}
		info := []byte(companyID)
		enc, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA512(), hpke.AES256GCM(), info)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt for the VSatellite: %w", err)
		}
		ciphertext, err := sender.Seal(info, plaintext)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt for the VSatellite: %w", err)
		}
		return base64.StdEncoding.EncodeToString(append(enc, ciphertext...)), nil

	default:
		return "", fmt.Errorf("unsupported VSatellite encryption key algorithm %q", keyAlgorithm)
	}
}
