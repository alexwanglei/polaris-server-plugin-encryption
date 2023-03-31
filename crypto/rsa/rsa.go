package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"

	"github.com/polarismesh/polaris-go/pkg/log"
)

// RSAKey RSA key pair
type RSAKey struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKey generate RSA key pair
func GenerateRSAKey() (*RSAKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	rsaKey := &RSAKey{
		PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey)),
		PublicKey:  base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)),
	}
	return rsaKey, nil
}

// Encrypt RSA encrypt plaintext using public key
func Encrypt(plaintext, publicKey []byte) ([]byte, error) {
	pub, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt RSA decrypt ciphertext using private key
func Decrypt(ciphertext, privateKey []byte) ([]byte, error) {
	priv, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		log.GetBaseLogger().Infof("[Config] Decrypt ParsePKCS1PrivateKey err:%v", err)
		return nil, err
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		log.GetBaseLogger().Infof("[Config] Decrypt DecryptPKCS1v15 err:%v", err)
		return nil, err
	}
	return plaintext, nil
}

// EncryptToBase64 RSA encrypt plaintext and base64 encode ciphertext
func EncryptToBase64(plaintext []byte, base64PublicKey string) (string, error) {
	pub, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return "", err
	}
	ciphertext, err := Encrypt(plaintext, pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptFromBase64 base64 decode ciphertext and RSA decrypt
func DecryptFromBase64(base64Ciphertext, base64PrivateKey string) ([]byte, error) {
	log.GetBaseLogger().Infof("[Config] DecryptFromBase64 base64Ciphertext:%s, base64PrivateKey:%s", base64Ciphertext, base64PrivateKey)
	priv, err := base64.StdEncoding.DecodeString(base64PrivateKey)
	if err != nil {
		log.GetBaseLogger().Infof("[Config] DecodeString base64PrivateKey err:%v", err)
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		log.GetBaseLogger().Infof("[Config] DecodeString base64Ciphertext err:%v", err)
		return nil, err
	}
	return Decrypt(ciphertext, priv)
}
