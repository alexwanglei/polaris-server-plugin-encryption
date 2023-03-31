package server

import (
	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto"
	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto/aes"
	"github.com/polarismesh/polaris/plugin"
)

const (
	PluginName       = "crypto"
	DefaultAlgorithm = aes.CryptorName
)

func init() {
	plugin.RegisterPlugin(PluginName, &serverCrypto{})
}

type serverCrypto struct {
	alog    string
	cryptor crypto.Cryptor
}

// Name 插件名词
func (s *serverCrypto) Name() string {
	return PluginName
}

// Initialize 初始化插件
func (s *serverCrypto) Initialize(conf *plugin.ConfigEntry) error {
	alog, ok := conf.Option["alog"]
	if !ok {
		s.alog = DefaultAlgorithm
	} else {
		s.alog = alog.(string)
	}
	if cryptor, ok := crypto.CryptorSet[s.alog]; ok {
		s.cryptor = cryptor
	} else {
		s.cryptor = crypto.CryptorSet[DefaultAlgorithm]
	}
	return nil
}

// Destroy 销毁插件
func (s *serverCrypto) Destroy() error {
	return nil
}

// Encrypt 加密
func (s *serverCrypto) Encrypt(plaintext string) (ciphertext string, key []byte, err error) {
	key, err = s.cryptor.GenerateKey()
	if err != nil {
		return
	}
	// 加密
	ciphertext, err = s.cryptor.EncryptToBase64([]byte(plaintext), key)
	if err != nil {
		return
	}
	return
}

// Decrypt 解密
func (s *serverCrypto) Decrypt(ciphertext string, key []byte) (string, error) {
	plaintext, err := s.cryptor.DecryptFromBase64(ciphertext, key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
