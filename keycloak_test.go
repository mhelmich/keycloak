package keycloak

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	_, err := GetStoreForFile("testdata/creds1.json")
	assert.Nil(t, err)
	_, err = GetStoreForFile("testdata/creds1.yaml")
	assert.Nil(t, err)
	_, err = GetStoreForFile("testdata/creds1.yml")
	assert.Nil(t, err)
	_, err = GetStoreForFile("doesntexist.json")
	assert.NotNil(t, err)
	_, err = GetStoreForFile("bad.format")
	assert.NotNil(t, err)
}
