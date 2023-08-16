package main

import (
	"flag"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	err := os.Setenv(coreutils.ReportUsage, "false")
	if err != nil {
		os.Exit(1)
	}
	// Disable progress bar and confirmation messages.
	err = os.Setenv(coreutils.CI, "true")
	if err != nil {
		os.Exit(1)
	}
	flag.Parse()
	result := m.Run()
	os.Exit(result)
}

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
	expectedVersion := fmt.Sprintf("Frogbot version %s", utils.FrogbotVersion)
	assert.Equal(t, expectedVersion, strings.TrimSpace(string(out)))
}
