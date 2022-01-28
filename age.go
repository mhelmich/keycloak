package keycloak

import (
	"bytes"
	"io"
	"io/ioutil"

	"filippo.io/age"
)

func newAgeEncryptionFunction(pubKey string) (encryptionFunc, error) {
	recipient, err := age.ParseX25519Recipient(pubKey)
	if err != nil {
		return nil, err
	}

	aesFunc, err := newAESEncryptionFunction()
	if err != nil {
		return nil, err
	}

	return func(bites []byte) ([]byte, error) {
		var buf bytes.Buffer
		var w io.WriteCloser
		var err error

		bites, err = aesFunc(bites)
		if err != nil {
			return nil, err
		}

		w, err = age.Encrypt(&buf, recipient)
		if err != nil {
			return nil, err
		}

		_, err = w.Write(bites)
		if err != nil {
			return nil, err
		}

		// close writer to flush all the data into the buffer
		err = w.Close()
		if err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}, nil
}

func newAgeDecryptionFunction(privKey string) (decryptionFunc, error) {
	identity, err := age.ParseX25519Identity(privKey)
	if err != nil {
		return nil, err
	}

	return func(bites []byte) ([]byte, error) {
		buf := bytes.NewBuffer(bites)
		r, err := age.Decrypt(buf, identity)
		if err != nil {
			return nil, err
		}

		bites, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}

		aesKey := bites[:32]
		bites = bites[32:]
		f, err := newAESDecryptionFunction((*[32]byte)(aesKey))
		if err != nil {
			return nil, err
		}

		return f(bites)
	}, nil
}
