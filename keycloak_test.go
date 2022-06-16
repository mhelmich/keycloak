package keycloak

import (
	"io/ioutil"
	"testing"

	"filippo.io/age"
	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	_, err := GetStoreForFile("testdata/creds1.json")
	assert.Nil(t, err)
	_, err = GetStoreForFile("testdata/creds2.json")
	assert.Nil(t, err)
	_, err = GetStoreForFile("testdata/creds1.yaml")
	assert.Nil(t, err)
	_, err = GetStoreForFile("testdata/creds1.yml")
	assert.Nil(t, err)
	_, err = GetStoreForFile("testdata/creds2.yml")
	assert.Nil(t, err)
	_, err = GetStoreForFile("doesntexist.json")
	assert.NotNil(t, err)
	_, err = GetStoreForFile("bad.format")
	assert.NotNil(t, err)
}

func TestMultiTreeFile(t *testing.T) {
	ageIdentity, err := age.GenerateX25519Identity()
	assert.Nil(t, err)
	ageRecipient := ageIdentity.Recipient()

	// encrypt subtrees independently
	store, err := GetStoreForFile("testdata/creds2.json")
	assert.Nil(t, err)
	err = store.EncryptSubtree(ageRecipient.String(), "secrets", "dev")
	assert.Nil(t, err)
	err = store.EncryptSubtree(ageRecipient.String(), "secrets", "stage")
	assert.Nil(t, err)
	err = store.EncryptSubtree(ageRecipient.String(), "secrets", "prod")
	assert.Nil(t, err)

	fd, err := ioutil.TempFile("", "TestMultiTreeFile1-")
	assert.Nil(t, err)
	defer fd.Close()
	err = store.ToFile(fd.Name())
	assert.Nil(t, err)

	bites, err := ioutil.ReadFile(fd.Name())
	assert.Nil(t, err)
	store2, err := GetStoreFromBytes(bites, JSON)
	assert.Nil(t, err)

	// decrypt subtrees independently
	err = store2.DecryptSubtree(ageIdentity.String(), "secrets", "prod")
	assert.Nil(t, err)
	err = store2.DecryptSubtree(ageIdentity.String(), "secrets", "dev")
	assert.Nil(t, err)
	err = store2.DecryptSubtree(ageIdentity.String(), "secrets", "stage")
	assert.Nil(t, err)
	fd2, err := ioutil.TempFile("", "TestMultiTreeFile2-")
	assert.Nil(t, err)
	defer fd2.Close()
	store2.ToFile(fd2.Name())

	// json diff the original file with the decrypted file
	originalBites, err := ioutil.ReadFile("testdata/creds2.json")
	assert.Nil(t, err)
	roundtripBites, err := ioutil.ReadFile(fd2.Name())
	assert.Nil(t, err)
	opts := jsondiff.DefaultConsoleOptions()
	diff, _ := jsondiff.Compare(originalBites, roundtripBites, &opts)
	assert.Equal(t, jsondiff.FullMatch, diff)
}
