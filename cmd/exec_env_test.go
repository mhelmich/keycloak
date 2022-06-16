package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecEnvBasic(t *testing.T) {
	m, err := decryptSubtree("../testdata/creds1.enc.yaml", "../testdata/keys.age", []string{"secrets"}, false)
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

func TestExecEnvPathIsDir(t *testing.T) {
	m, err := decryptSubtree("../testdata", "../testdata/keys.age", []string{}, false)
	assert.NotNil(t, err)
	assert.Nil(t, m)
}

func TestExecEnvNoJsonPath(t *testing.T) {
	envBefore := os.Environ()
	cmd, err := buildCommandForExecEnv("../testdata/creds2.enc.yaml", "../testdata/keys.age", "", false)
	assert.Nil(t, err)
	assert.Equal(t, len(envBefore)+2, len(cmd.Env))
}

// func TestNarf(t *testing.T) {
// 	store, err := kk.GetStoreForFile("../testdata/creds3.yml")
// 	assert.Nil(t, err)
// 	err = store.EncryptSubtree("age133p5vy8lw48dw59jdl7rrlpm50dslc6m6kpjc3slaq2edmqayyas5pv8se")
// 	assert.Nil(t, err)
// 	err = store.ToFile("../testdata/creds2.enc.yaml")
// 	assert.Nil(t, err)
// }
