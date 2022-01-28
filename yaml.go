package keycloak

import (
	"io/ioutil"

	k8syaml "sigs.k8s.io/yaml"
)

func newYAMLStore(bites []byte) (*yamlStore, error) {
	jsonBites, err := k8syaml.YAMLToJSONStrict(bites)
	if err != nil {
		return nil, err
	}

	js, err := newJSONStore(jsonBites)
	if err != nil {
		return nil, err
	}

	return &yamlStore{
		js: js,
	}, nil
}

type yamlStore struct {
	js *jsonStore
}

func (s *yamlStore) EncryptSubtree(recipient string, path ...string) error {
	return s.js.EncryptSubtree(recipient, path...)
}

func (s *yamlStore) DecryptSubtree(identity string, path ...string) error {
	return s.js.DecryptSubtree(identity, path...)
}

func (s *yamlStore) Subtree(path ...string) (map[string]interface{}, error) {
	return s.js.Subtree(path...)
}

func (s *yamlStore) ToFile(path string) error {
	bites, err := s.js.bytes()
	if err != nil {
		return err
	}

	yamlBites, err := k8syaml.JSONToYAML(bites)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, yamlBites, 0600)
}
