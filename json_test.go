package keycloak

import (
	"io/ioutil"
	"testing"

	"filippo.io/age"
	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
)

func TestJSONBasic(t *testing.T) {
	jsons := []string{
		"testdata/creds1.json",
	}

	for idx := range jsons {
		runTestJSONBasic(t, jsons[idx])
	}
}

func runTestJSONBasic(t *testing.T, filepath string) {
	bites, err := ioutil.ReadFile(filepath)
	assert.Nil(t, err)
	jStore, err := newJSONStore(bites)
	assert.Nil(t, err)

	ageIdentity, err := age.GenerateX25519Identity()
	assert.Nil(t, err)
	ageRecipient := ageIdentity.Recipient()

	err = jStore.EncryptSubtree(ageRecipient.String())
	assert.Nil(t, err)

	err = jStore.DecryptSubtree(ageIdentity.String())
	assert.Nil(t, err)

	fd, err := ioutil.TempFile("", "TestJSONBasic-")
	assert.Nil(t, err)
	defer fd.Close()
	err = jStore.ToFile(fd.Name())
	assert.Nil(t, err)

	bites2, err := ioutil.ReadFile(fd.Name())
	assert.Nil(t, err)
	opts := jsondiff.DefaultConsoleOptions()
	diff, _ := jsondiff.Compare(bites, bites2, &opts)
	assert.Equal(t, jsondiff.FullMatch, diff)
}
