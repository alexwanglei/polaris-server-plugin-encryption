package crypto

import "fmt"

var CryptorSet = make(map[string]Cryptor)

// RegisterCryptor register cryptor
func RegisterCryptor(name string, cryptor Cryptor) {
	if _, exist := CryptorSet[name]; exist {
		panic(fmt.Sprintf("existed cryptor: name=%v", name))
	}
	CryptorSet[name] = cryptor
}

type Cryptor interface {
	GenerateKey() ([]byte, error)
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
	EncryptToBase64(plaintext, key []byte) (string, error)
	DecryptFromBase64(base64Ciphertext string, key []byte) ([]byte, error)
}
