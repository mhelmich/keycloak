package keycloak

import "hash"

type encryptionFunc func([]byte) ([]byte, error)

type decryptionFunc func([]byte) ([]byte, error)

type hashingFunc func([]byte) error

type hasher struct {
	hash.Hash
}

func (h *hasher) write(bites []byte) error {
	_, err := h.Write(bites)
	return err
}

func joinSize(size int, s ...[]byte) []byte {
	i := 0
	b := make([]byte, size)
	for _, v := range s {
		i += copy(b[i:], v)
	}
	return b
}
