package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChdir(t *testing.T) {
	originCwd, err := os.Getwd()
	assert.NoError(t, err)

	callback, err := Chdir("..")
	assert.NoError(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, filepath.Dir(originCwd), cwd)

	callback()
	cwd, err = os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, originCwd, cwd)
}

func TestChdirErr(t *testing.T) {
	originCwd, err := os.Getwd()
	assert.NoError(t, err)

	_, err = Chdir("not-existed")
	assert.Error(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, originCwd, cwd)
}
