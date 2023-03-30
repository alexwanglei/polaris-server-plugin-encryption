package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRSAKey(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "generate rsa key",
			err:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRSAKey()
			t.Logf("PrivateKey: %s", got.PrivateKey)
			t.Logf("PublicKey: %s", got.PublicKey)
			assert.Nil(t, err)
		})
	}
}

func TestEncryptToBase64(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name string
		args args
		want string
		err  error
	}{
		{
			name: "encrypt to base64",
			args: args{
				plaintext: []byte("1234abcd!@#$"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rasKey, err := GenerateRSAKey()
			assert.Nil(t, err)
			ciphertext, err := EncryptToBase64(tt.args.plaintext, rasKey.PublicKey)
			assert.Nil(t, err)
			plaintext, err := DecryptFromBase64(ciphertext, rasKey.PrivateKey)
			assert.Nil(t, err)
			assert.Equal(t, plaintext, tt.args.plaintext)
		})
	}
}
