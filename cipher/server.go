package encrypt

import (
	"github.com/polarismesh/polaris/plugin"
)

const PluginName = "ServerCipher"

func init() {
	plugin.RegisterPlugin(PluginName, &serverCipher{})
}

type serverCipher struct {
}

// Name 插件名词
func (s *serverCipher) Name() string {
	return PluginName
}

// Initialize 初始化插件
func (s *serverCipher) Initialize(conf *plugin.ConfigEntry) error {
	return nil
}

// Destroy 销毁插件
func (s *serverCipher) Destroy() error {
	return nil
}
