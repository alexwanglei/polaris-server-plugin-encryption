package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto"
)

const (
	// CryptorName cryptor name
	CryptorName = "AES"
)

func init() {
	crypto.RegisterCryptor(CryptorName, &aesCryptor{})
}

// aesCryptor AES cryptor
type aesCryptor struct {
}

// New new AES cryptor
func New() *aesCryptor {
	return &aesCryptor{}
}

// GenerateKey generate key
func (c *aesCryptor) GenerateKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt AES encryption
func (c *aesCryptor) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	paddingData := pkcs7Padding(plaintext, blockSize)
	ciphertext := make([]byte, len(paddingData))
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(ciphertext, paddingData)
	return ciphertext, nil
}

// Decrypt AES decryption
func (c *aesCryptor) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	paddingPlaintext := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(paddingPlaintext, ciphertext)
	plaintext, err := pkcs7UnPadding(paddingPlaintext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// EncryptToBase64 AES encrypt plaintext and base64 encode ciphertext
func (c *aesCryptor) EncryptToBase64(plaintext, key []byte) (string, error) {
	ciphertext, err := c.Encrypt(plaintext, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptFromBase64 base64 decode ciphertext and AES decrypt
func (c *aesCryptor) DecryptFromBase64(base64Ciphertext string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext, key)
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid encryption data")
	}
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}
