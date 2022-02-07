package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	kk "github.com/mhelmich/keycloak"
	"github.com/spf13/cobra"
)

var (
	fileParam                string
	keyFileParam             string
	jsonPathParam            string
	deletePrivateKeyAfterUse bool
)

// execEnvCmd represents the execEnv command
var execEnvCmd = &cobra.Command{
	Use:   "exec-env",
	Short: "Start a child process with secrets in the environment.",
	Long:  `Note bene: exec-env does not verify the path in any shape or form.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		file, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}

		file, err = filepath.Abs(file)
		if err != nil {
			return err
		}

		keyFile, err := cmd.Flags().GetString("key")
		if err != nil {
			return err
		}

		jsonPath, err := cmd.Flags().GetString("json-path")
		if err != nil {
			return err
		}

		jsonPathParts := strings.Split(jsonPath, ".")
		return execEnv(file, keyFile, jsonPathParts, deletePrivateKeyAfterUse, args...)
	},
}

func execEnv(filePath string, keyFile string, jsonPath []string, deletePrivateKeyAfterUse bool, command ...string) error {
	// decrypt subtree in file
	st, err := decryptSubtree(filePath, keyFile, jsonPath, deletePrivateKeyAfterUse)
	if err != nil {
		return err
	}

	// set secrets into env
	env, err := getEnvWithSecrets(st)
	if err != nil {
		return err
	}

	// // start child process
	cmd := prepareCommand(command, env)
	return cmd.Run()
}

func decryptSubtree(filePath string, keyFile string, jsonPath []string, deletePrivateKeyAfterUse bool) (map[string]interface{}, error) {
	key, err := getKey(keyFile, deletePrivateKeyAfterUse)
	if err != nil {
		return nil, err
	}

	// if no file with encrypted secrets exists,
	// just return an empty map
	_, err = os.Stat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]interface{}{}, nil
	}

	store, err := kk.GetStoreForFile(filePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	err = store.DecryptSubtree(key, jsonPath...)
	if err != nil {
		return nil, err
	}

	return store.Subtree(jsonPath...)
}

func getEnvWithSecrets(st map[string]interface{}) ([]string, error) {
	env := os.Environ()
	for key, value := range st {
		switch v := value.(type) {
		case string:
			env = append(env, fmt.Sprintf("%s=%s", toScreamingSnake(key), v))
		case float64:
			env = append(env, fmt.Sprintf("%s=%f", toScreamingSnake(key), v))
		default:
			return nil, fmt.Errorf("invalid type")
		}
	}
	return env, nil
}

func prepareCommand(command []string, env []string) *exec.Cmd {
	var args []string
	args = append(args, "-c")
	args = append(args, command...)
	cmd := exec.Command("/bin/sh", args...)

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func getKey(path string, deletePrivateKeyAfterUse bool) (string, error) {
	var bites []byte
	var err error

	if deletePrivateKeyAfterUse {
		defer func() {
			if path != "" {
				_ = os.Remove(path)
			}
			_ = os.Setenv("AGE_KEY", "")
		}()
	}

	if path != "" {
		// try given path
		bites, err = ioutil.ReadFile(path)
		if err == nil {
			r := bufio.NewReader(bytes.NewBuffer(bites))
			var line string

			for {
				line, err = r.ReadString('\n')
				if err != nil && err != io.EOF {
					return "", err
				}

				if strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
					return strings.TrimSpace(line), nil
				}

				if err == io.EOF {
					return "", fmt.Errorf("did not find a suitable private key")
				}
			}
		}
	}

	// TODO: try default file location
	// try env var
	v := os.Getenv("AGE_KEY")
	if v != "" {
		return v, nil
	}
	return "", fmt.Errorf("cannot find age key")
}

// taken from: https://github.com/iancoleman/strcase/blob/a61ebb85b34d7b831590cd8fa7faafadc161a652/snake.go#L66
// ToScreamingSnake converts a string to SCREAMING_SNAKE_CASE
func toScreamingSnake(s string) string {
	return toScreamingDelimited(s, '_', "", true)
}

// toScreamingDelimited converts a string to SCREAMING.DELIMITED.SNAKE.CASE
// (in this case `delimiter = '.'; screaming = true`)
// or delimited.snake.case
// (in this case `delimiter = '.'; screaming = false`)
func toScreamingDelimited(s string, delimiter uint8, ignore string, screaming bool) string {
	s = strings.TrimSpace(s)
	n := strings.Builder{}
	n.Grow(len(s) + 2) // nominal 2 bytes of extra space for inserted delimiters
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if vIsLow && screaming {
			v += 'A'
			v -= 'a'
		} else if vIsCap && !screaming {
			v += 'a'
			v -= 'A'
		}

		// treat acronyms as words, eg for JSONData -> JSON is a whole word
		if i+1 < len(s) {
			next := s[i+1]
			vIsNum := v >= '0' && v <= '9'
			nextIsCap := next >= 'A' && next <= 'Z'
			nextIsLow := next >= 'a' && next <= 'z'
			nextIsNum := next >= '0' && next <= '9'
			// add underscore if next letter case type is changed
			if (vIsCap && (nextIsLow || nextIsNum)) || (vIsLow && (nextIsCap || nextIsNum)) || (vIsNum && (nextIsCap || nextIsLow)) {
				prevIgnore := ignore != "" && i > 0 && strings.ContainsAny(string(s[i-1]), ignore)
				if !prevIgnore {
					if vIsCap && nextIsLow {
						if prevIsCap := i > 0 && s[i-1] >= 'A' && s[i-1] <= 'Z'; prevIsCap {
							n.WriteByte(delimiter)
						}
					}
					n.WriteByte(v)
					if vIsLow || vIsNum || nextIsNum {
						n.WriteByte(delimiter)
					}
					continue
				}
			}
		}

		if (v == ' ' || v == '_' || v == '-' || v == '.') && !strings.ContainsAny(string(v), ignore) {
			// replace space/underscore/hyphen/dot with delimiter
			n.WriteByte(delimiter)
		} else {
			n.WriteByte(v)
		}
	}

	return n.String()
}

func init() {
	rootCmd.AddCommand(execEnvCmd)
	execEnvCmd.Flags().StringVarP(&fileParam, "file", "f", "", "the secrets file to read (required)")
	_ = execEnvCmd.MarkFlagRequired("file")
	execEnvCmd.Flags().StringVarP(&keyFileParam, "key", "k", "", "the private key file to read")
	execEnvCmd.Flags().StringVarP(&jsonPathParam, "json-path", "p", "secrets", "the json path to the subtree to decrypt")
	execEnvCmd.Flags().BoolVarP(&deletePrivateKeyAfterUse, "delete-private-key-after-use", "d", false, "deletes the private key locally after use")
}
