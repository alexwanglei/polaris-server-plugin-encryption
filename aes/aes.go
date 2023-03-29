package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// GenerateKey 生成Key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt 加密
func Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	paddingData := pkcs7Padding(data, blockSize)
	crypted := make([]byte, len(paddingData))
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(crypted, paddingData)
	return crypted, nil
}

// Decrypt 解密
func Decrypt(crypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	paddingData := make([]byte, len(crypted))
	blockMode.CryptBlocks(paddingData, crypted)
	data, err := pkcs7UnPadding(paddingData)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// EncryptToBase64 AES encrypt plaintext and base64 encode ciphertext
func EncryptToBase64(plaintext, key []byte) (string, error) {
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptFromBase64 base64 decode ciphertext and AES decrypt
func DecryptFromBase64(base64Ciphertext string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Ciphertext)
	if err != nil {
		return nil, err
	}
	return Decrypt(ciphertext, key)
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
