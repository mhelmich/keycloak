package keycloak

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func TestEncryptDecryptGCM(t *testing.T) {
	randomKey := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, randomKey[:])
	if err != nil {
		t.Fatal(err)
	}

	gcmTests := []struct {
		plaintext []byte
		key       *[32]byte
	}{
		{
			plaintext: []byte("Hello, world!"),
			key:       randomKey,
		},
	}

	for _, tt := range gcmTests {
		ciphertext, err := aesEncrypt(tt.plaintext, tt.key)
		if err != nil {
			t.Fatal(err)
		}

		plaintext, err := aesDecrypt(ciphertext, tt.key)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(plaintext, tt.plaintext) {
			t.Errorf("plaintexts don't match")
		}

		ciphertext[0] ^= 0xff
		_, err = aesDecrypt(ciphertext, tt.key)
		if err == nil {
			t.Errorf("gcmOpen should not have worked, but did")
		}
	}
}

func BenchmarkAESGCM(b *testing.B) {
	randomKey := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, randomKey[:])
	if err != nil {
		b.Fatal(err)
	}

	data, err := ioutil.ReadFile("testdata/big")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, _ = aesEncrypt(data, randomKey)
	}
}

func BenchmarkSecretbox(b *testing.B) {
	randomKey := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, randomKey[:])
	if err != nil {
		b.Fatal(err)
	}

	nonce := &[24]byte{}
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		b.Fatal(err)
	}

	data, err := ioutil.ReadFile("testdata/big")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		secretbox.Seal(nil, data, nonce, randomKey)
	}
}
