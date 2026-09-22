//go:build mobile && (linux || android)

package mobile

import (
	"errors"
	"github.com/tjjh89017/stunmesh-go/internal/validation"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GeneratePrivateKey is an in-process enrollment operation using WireGuard's
// existing key primitive. It is never a network enrollment/authentication API.
func GeneratePrivateKey() (string, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", errors.New("key generation failed")
	}
	defer clear(key[:])
	return key.String(), nil
}
func PublicKey(private string) (string, error) {
	raw, err := keyToBytes(private)
	if err != nil {
		return "", errors.New("invalid local key")
	}
	defer clear(raw[:])
	return wgtypes.Key(raw).PublicKey().String(), nil
}
func ValidateConfig(text string) error { _, err := parseConfig(text); return err }

// ValidatePublicKey uses the standard X25519 low-order input check.
func ValidatePublicKey(key string) error { _, err := validation.PublicKey(key); return err }
