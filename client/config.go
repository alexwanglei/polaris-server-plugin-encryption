package client

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"
)

type Config struct {
	Algorithm string `yaml:"algorithm" json:"algorithm"`
}

// GetAlgorithm get config.configFilter algorithm
func (c *Config) GetAlgorithm() string {
	return c.Algorithm
}

// SetAlgorithm set config.configFilter algorithm
func (c *Config) SetAlgorithm(algorithm string) {
	c.Algorithm = algorithm
}

// Verify verify config.configFilter
func (c *Config) Verify() error {
	if nil == c {
		return errors.New("ConfigFilterConfig is nil")
	}
	var errs error
	if c.Algorithm == "" {
		errs = multierror.Append(errs, fmt.Errorf("config.ConfigFilter.algorithm is empty"))
	}
	return errs
}

// SetDefault set default config.configFilter
func (c *Config) SetDefault() {
	if c.Algorithm == "" {
		c.Algorithm = DefaultAlgorithm
	}
}
