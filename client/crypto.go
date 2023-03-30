package client

import (
	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto"
	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto/aes"
	"github.com/polarismesh/polaris-go/pkg/config"
	"github.com/polarismesh/polaris-go/pkg/model"
	"github.com/polarismesh/polaris-go/pkg/plugin"
	"github.com/polarismesh/polaris-go/pkg/plugin/common"
)

const (
	PluginName       = "clientCrypto"
	DefaultAlgorithm = aes.CryptorName
)

func init() {
	plugin.RegisterConfigurablePlugin(&clientCrypto{}, nil)
}

type clientCrypto struct {
	*plugin.PluginBase
	alog    string
	cryptor crypto.Cryptor
}

// Type 插件类型.
func (c *clientCrypto) Type() common.Type {
	return common.TypeConfigConnector
}

// Name 插件名
func (c *clientCrypto) Name() string {
	return PluginName
}

// Init 初始化插件
func (c *clientCrypto) Init(ctx *plugin.InitContext) error {
	c.PluginBase = plugin.NewPluginBase(ctx)

	// if cryptor, ok := crypto.CryptorSet[s.alog]; ok {
	// 	s.cryptor = cryptor
	// } else {
	// 	s.cryptor = crypto.CryptorSet[DefaultAlgorithm]
	// }
	return nil
}

// Destroy 销毁插件
func (c *clientCrypto) Destroy() error {
	return nil
}

// IsEnable enable
func (c *clientCrypto) IsEnable(cfg config.Configuration) bool {
	return cfg.GetGlobal().GetSystem().GetMode() != model.ModeWithAgent
}

// Encrypt 加密
func (c *clientCrypto) Encrypt(plaintext string) (ciphertext string, key []byte, err error) {
	key, err = c.cryptor.GenerateKey()
	if err != nil {
		return
	}
	// 加密
	ciphertext, err = c.cryptor.EncryptToBase64([]byte(plaintext), key)
	if err != nil {
		return
	}
	return
}

// Decrypt 解密
func (c *clientCrypto) Decrypt(ciphertext string, key []byte) (string, error) {
	plaintext, err := c.cryptor.DecryptFromBase64(ciphertext, key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
