package keycloak

import (
	"io/ioutil"
	"testing"

	"filippo.io/age"
	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
	k8syaml "sigs.k8s.io/yaml"
)

func TestYAMLBasic(t *testing.T) {
	yamls := []struct {
		file string
		path []string
	}{
		{
			file: "testdata/creds1.yaml",
			path: []string{"secrets"},
		},
	}

	for _, test := range yamls {
		runTestYAMLBasic(t, test.file, test.path)
	}
}

func runTestYAMLBasic(t *testing.T, file string, path []string) {
	bites, err := ioutil.ReadFile(file)
	assert.Nil(t, err)
	yStore, err := newYAMLStore(bites)
	assert.Nil(t, err)

	ageIdentity, err := age.GenerateX25519Identity()
	assert.Nil(t, err)
	ageRecipient := ageIdentity.Recipient()

	err = yStore.EncryptSubtree(ageRecipient.String(), path...)
	assert.Nil(t, err)

	err = yStore.DecryptSubtree(ageIdentity.String(), path...)
	assert.Nil(t, err)

	fd, err := ioutil.TempFile("", "TestYAMLBasic-")
	assert.Nil(t, err)
	defer fd.Close()
	err = yStore.ToFile(fd.Name())
	assert.Nil(t, err)

	bites2, err := ioutil.ReadFile(fd.Name())
	assert.Nil(t, err)
	jsonBites, err := k8syaml.YAMLToJSONStrict(bites)
	assert.Nil(t, err)
	jsonBites2, err := k8syaml.YAMLToJSONStrict(bites2)
	assert.Nil(t, err)
	opts := jsondiff.DefaultConsoleOptions()
	diff, _ := jsondiff.Compare(jsonBites, jsonBites2, &opts)
	assert.Equal(t, jsondiff.FullMatch, diff)
}
