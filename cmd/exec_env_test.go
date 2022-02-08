package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecEnvBasic(t *testing.T) {
	m, err := decryptSubtree("../testdata/creds1.enc.yaml", "../testdata/keys.age", []string{"secrets"}, true)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(m))

	envBefore := os.Environ()
	env, err := getEnvWithSecrets(m)
	assert.Nil(t, err)
	assert.Equal(t, len(envBefore)+3, len(env))

	cmd := prepareCommand([]string{"runner.sh"}, env)
	assert.Equal(t, len(env), len(cmd.Env))
	assert.Equal(t, "/bin/sh -c runner.sh", cmd.String())
}

func TestExecEnvNoSecretFile(t *testing.T) {
	m, err := decryptSubtree("does/not/exist", "../testdata/keys.age", []string{}, false)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(m))
}
