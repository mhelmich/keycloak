package keycloak

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"sort"
	"strconv"
)

type jsonDataType int8

const (
	stringType jsonDataType = 0
	numberType jsonDataType = 1
)

func newJSONStore(bites []byte) (*jsonStore, error) {
	root := make(map[string]interface{})
	err := json.Unmarshal(bites, &root)
	if err != nil {
		return nil, err
	}

	return &jsonStore{
		root: root,
	}, nil
}

type jsonStore struct {
	root interface{}
}

func (s *jsonStore) EncryptSubtree(recipient string, path ...string) error {
	st, err := subtree(s.root, path...)
	if err != nil {
		return err
	}

	ef, err := newAgeEncryptionFunction(recipient)
	if err != nil {
		return err
	}

	newRoot, ok := st.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid subtree")
	}

	return encryptSubtree(newRoot, ef, "1234567890")
}

func (s *jsonStore) DecryptSubtree(identity string, path ...string) error {
	st, err := subtree(s.root, path...)
	if err != nil {
		return err
	}

	df, err := newAgeDecryptionFunction(identity)
	if err != nil {
		return err
	}

	newRoot, ok := st.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid subtree")
	}

	return decryptSubTree(newRoot, df, "1234567890")
}

func (s *jsonStore) Subtree(path ...string) (map[string]interface{}, error) {
	st, err := subtree(s.root, path...)
	if err != nil {
		return nil, err
	}

	m, ok := st.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid subtree")
	}

	return m, nil
}

func (s *jsonStore) ToFile(path string) error {
	bites, err := s.bytes()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, bites, 0600)
}

func (s *jsonStore) bytes() ([]byte, error) {
	return json.Marshal(s.root)
}

func subtree(v interface{}, path ...string) (interface{}, error) {
	return traversePath(v, path...)
}

func encryptSubtree(v map[string]interface{}, ef encryptionFunc, serviceName string) error {
	hsher := &hasher{hmac.New(sha512.New512_256, []byte(serviceName))}
	err := encryptSubtreeWithHasher(v, ef, hsher.write)
	if err != nil {
		return err
	}

	encHash, err := ef(hsher.Sum(nil))
	if err != nil {
		return err
	}

	v["__mac__"] = base64.StdEncoding.EncodeToString(encHash)
	return nil
}

func encryptSubtreeWithHasher(v map[string]interface{}, ef encryptionFunc, hf hashingFunc) error {
	_, err := traverseEncrypt(v, ef, hf)
	return err
}

func decryptSubTree(v map[string]interface{}, df decryptionFunc, serviceName string) error {
	hsher := &hasher{hmac.New(sha512.New512_256, []byte(serviceName))}

	m, ok := v["__mac__"]
	if !ok {
		return fmt.Errorf("cannot find mac")
	}

	delete(v, "__mac__")
	err := decryptSubTreeWithHasher(v, df, hsher.write)
	if err != nil {
		return err
	}

	mac, ok := m.(string)
	if !ok {
		return fmt.Errorf("invalid mac")
	}

	macBites, err := base64.StdEncoding.DecodeString(mac)
	if err != nil {
		return err
	}

	macBites, err = df(macBites)
	if err != nil {
		return err
	}

	hSum := hsher.Sum(nil)
	if !bytes.Equal(macBites, hSum) {
		return fmt.Errorf("invalid mac")
	}

	return nil
}

func decryptSubTreeWithHasher(v map[string]interface{}, df decryptionFunc, hf hashingFunc) error {
	_, err := traverseDecrypt(v, df, hf)
	return err
}

func traversePath(v interface{}, path ...string) (interface{}, error) {
	if len(path) == 0 {
		return v, nil
	}

	switch v := v.(type) {
	case []interface{}:
		if len(v) == 0 {
			return nil, fmt.Errorf("invalid path")
		}

		i, err := strconv.ParseInt(path[0], 10, 32)
		if err != nil {
			return nil, err
		}

		return traversePath(v[i], path[1:]...)

	case map[string]interface{}:
		v1, ok := v[path[0]]
		if !ok {
			return nil, fmt.Errorf("invalid path")
		}

		return traversePath(v1, path[1:]...)

	case string:
		if len(path) != 0 {
			return nil, fmt.Errorf("invalid path")
		}

		return v, nil
	case float64:
		if len(path) != 0 {
			return nil, fmt.Errorf("invalid path")
		}

		return v, nil

	default:
		return nil, fmt.Errorf("unknown type %T", v)
	}
}

func traverseDecrypt(v interface{}, df decryptionFunc, hf hashingFunc) (interface{}, error) {
	switch v := v.(type) {
	case []interface{}:
		for idx := range v {
			newV, err := traverseDecrypt(v[idx], df, hf)
			if err != nil {
				return nil, err
			}

			if newV != nil {
				v[idx] = newV
			}
		}
		return "", nil

	case map[string]interface{}:
		keys := make([]string, len(v))
		idx := 0
		for key := range v {
			keys[idx] = key
			idx++
		}

		sort.Strings(keys)
		for _, key := range keys {
			newV, err := traverseDecrypt(v[key], df, hf)
			if err != nil {
				return nil, err
			}

			if newV != nil {
				v[key] = newV
			}
		}
		return nil, nil

	case string:
		bites, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}

		typeByte := bites[0]
		bites = bites[1:]
		data, err := df(bites)
		if err != nil {
			return nil, err
		}

		err = hf(data)
		if err != nil {
			return nil, err
		}

		switch jsonDataType(typeByte) {
		case stringType:
			return string(data), nil

		case numberType:
			return math.Float64frombits(binary.BigEndian.Uint64(data)), nil

		default:
			return "", fmt.Errorf("invalid type")
		}

	default:
		return "", fmt.Errorf("invalid type")
	}
}

func traverseEncrypt(v interface{}, ef encryptionFunc, hf hashingFunc) (string, error) {
	var newV string
	var bites []byte
	var err error
	switch v := v.(type) {
	case []interface{}:
		for idx := range v {
			newV, err = traverseEncrypt(v[idx], ef, hf)
			if err != nil {
				return "", err
			}

			if len(newV) > 0 {
				v[idx] = newV
			}
		}
		return "", nil

	case map[string]interface{}:
		keys := make([]string, len(v))
		idx := 0
		for key := range v {
			keys[idx] = key
			idx++
		}

		sort.Strings(keys)
		for _, key := range keys {
			newV, err = traverseEncrypt(v[key], ef, hf)
			if err != nil {
				return "", err
			}

			if len(newV) > 0 {
				v[key] = newV
			}
		}
		return "", nil

	case string:
		bites, err = ef([]byte(v))
		if err != nil {
			return "", err
		}

		if hf != nil {
			err = hf([]byte(v))
			if err != nil {
				return "", err
			}
		}

		bites = joinSize(1+len(bites), []byte{byte(stringType)}, bites)
		return base64.StdEncoding.EncodeToString(bites), nil

	case float64:
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(v))
		bites, err := ef(buf[:])
		if err != nil {
			return "", err
		}

		if hf != nil {
			err = hf(buf[:])
			if err != nil {
				return "", err
			}
		}

		bites = joinSize(1+len(bites), []byte{byte(numberType)}, bites)
		return base64.StdEncoding.EncodeToString(bites), nil

	default:
		return "", fmt.Errorf("unknown type %s", v)
	}
}
