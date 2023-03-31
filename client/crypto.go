package client

import (
	"encoding/json"

	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto"
	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto/aes"
	"github.com/alexwanglei/polaris-server-plugin-encryption/crypto/rsa"
	"github.com/polarismesh/polaris-go/pkg/config"
	"github.com/polarismesh/polaris-go/pkg/log"
	"github.com/polarismesh/polaris-go/pkg/model"
	"github.com/polarismesh/polaris-go/pkg/plugin"
	"github.com/polarismesh/polaris-go/pkg/plugin/common"
	"github.com/polarismesh/polaris-go/pkg/plugin/configconnector"
	"github.com/polarismesh/polaris-go/pkg/plugin/configfilter"
)

// ConfigFileHandleFunc 配置文件处理函数
// type ConfigFileHandleFunc func(configFile *configconnector.ConfigFile) (*configconnector.ConfigFileResponse, error)

const (
	PluginName       = "crypto"
	DefaultAlgorithm = aes.CryptorName
)

func init() {
	plugin.RegisterConfigurablePlugin(&CryptoFilter{}, &Config{})
}

type CryptoFilter struct {
	*plugin.PluginBase
	cfg        *Config
	alog       string
	cryptor    crypto.Cryptor
	privateKey *rsa.RSAKey
}

// Type 插件类型.
func (c *CryptoFilter) Type() common.Type {
	return 0x1015
}

// Name 插件名
func (c *CryptoFilter) Name() string {
	return PluginName
}

// Init 初始化插件
func (c *CryptoFilter) Init(ctx *plugin.InitContext) error {
	c.PluginBase = plugin.NewPluginBase(ctx)

	cfgValue := ctx.Config.GetConfigFile().GetConfigFilterConfig().GetPluginConfig(c.Name())
	if cfgValue != nil {
		c.cfg = cfgValue.(*Config)
	}
	if cryptor, ok := crypto.CryptorSet[c.cfg.Algorithm]; ok {
		c.cryptor = cryptor
	} else {
		c.cryptor = crypto.CryptorSet[DefaultAlgorithm]
	}
	return nil
}

// Destroy 销毁插件
func (c *CryptoFilter) Destroy() error {
	return nil
}

// IsEnable enable
func (c *CryptoFilter) IsEnable(cfg config.Configuration) bool {
	return cfg.GetGlobal().GetSystem().GetMode() != model.ModeWithAgent
}

func (c *CryptoFilter) DoFilter(configFile *configconnector.ConfigFile, next configfilter.ConfigFileHandleFunc) configfilter.ConfigFileHandleFunc {
	return func(configFile *configconnector.ConfigFile) (*configconnector.ConfigFileResponse, error) {
		log.GetBaseLogger().Infof("[Config] do filter: configFile:%s\n", jsonify(configFile))
		// 如果是加密配置，生成公钥和私钥，
		if configFile.GetIsEncrypted() {
			privateKey, err := rsa.GenerateRSAKey()
			if err != nil {
				return nil, err
			}
			configFile.PublicKey = privateKey.PublicKey
			c.privateKey = privateKey
		}

		resp, err := next(configFile)
		if err != nil {
			return resp, err
		}
		log.GetBaseLogger().Infof("[Config] next resp:%s\n", jsonify(resp))
		// 如果是加密配置
		if resp.GetConfigFile().GetIsEncrypted() && resp.GetConfigFile().GetContent() != "" {
			// 返回了数据密钥，解密配置
			if resp.GetConfigFile().GetDataKey() != "" {
				dataKey, err := rsa.DecryptFromBase64(resp.GetConfigFile().GetDataKey(), c.privateKey.PrivateKey)
				if err != nil {
					log.GetBaseLogger().Infof("[Config] rsa decrypt err:%v", err)
					return nil, err
				}
				plainContent, err := c.cryptor.DecryptFromBase64(resp.GetConfigFile().GetContent(), dataKey)
				if err != nil {
					return nil, err
				}
				resp.ConfigFile.Content = string(plainContent)
			} else {
				// 没有返回数据密钥，设置为加密配置重新请求
				configFile.IsEncrypted = true
				return c.DoFilter(configFile, next)(configFile)
			}
		}
		return resp, err
	}
}

func jsonify(data interface{}) string {
	if data != nil {
		bytes, _ := json.Marshal(data)
		return string(bytes)
	}
	return ""
}
