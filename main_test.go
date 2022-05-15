package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	defer func() {
		os.Stdout = originalStdout
	}()
	os.Stdout = w

	os.Args = []string{"frogbot", "--version"}
	main()

	assert.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, "Frogbot version 0.0.0", strings.TrimSpace(string(out)))
}
