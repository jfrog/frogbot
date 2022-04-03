package testdata

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func SetEnvAndAssert(t *testing.T, env map[string]string) func() {
	var previousValues = make(map[string]string)
	for key, val := range env {
		previousValues[key] = os.Getenv(key)
		setEnvAndAssert(t, key, val)
	}

	return func() {
		for key, _ := range env {
			setEnvAndAssert(t, key, previousValues[key])
		}
	}
}

func setEnvAndAssert(t *testing.T, key, value string) {
	assert.NoError(t, os.Setenv(key, value))
}

