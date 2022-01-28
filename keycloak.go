package keycloak

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
)

// The file format of an encrypted file.
type FileFormat int

const (
	// JSON -
	JSON FileFormat = iota
	// YAML -
	YAML
)

// Store defines an encrypted data file.
// Files are assumed to be tree-structured (or at least eflat arrays).
// This interface allows users to do basic operations on these secret files.
type Store interface {
	// EncryptSubtree -
	EncryptSubtree(string, ...string) error
	// DecryptSubtree -
	DecryptSubtree(string, ...string) error
	// Subtree -
	Subtree(...string) (map[string]interface{}, error)
	// ToFile -
	ToFile(string) error
}

// GetStoreForFile -
func GetStoreForFile(path string) (Store, error) {
	frmt, err := getFormat(path)
	if err != nil {
		return nil, err
	}

	return GetStoreWithFormat(path, frmt)
}

// GetStoreWithFormat -
func GetStoreWithFormat(path string, frmt FileFormat) (Store, error) {
	bites, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	switch frmt {
	case JSON:
		return newJSONStore(bites)
	case YAML:
		return newYAMLStore(bites)
	default:
		return nil, fmt.Errorf("invalid format")
	}
}

func getFormat(path string) (FileFormat, error) {
	switch filepath.Ext(path) {
	case ".json":
		return JSON, nil
	case ".yaml", ".yml":
		return YAML, nil
	default:
		return JSON, fmt.Errorf("unsupported format: %s", filepath.Ext(path))
	}
}
