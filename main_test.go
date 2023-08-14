package main

import (
	"flag"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	FrogbotModuleName = "github.com/jfrog/frogbot"
)

func TestRunner(t *testing.T) {
	// Create temp jfrog home
	cleanUpJfrogHome, err := coreTests.SetJfrogHome()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	// Clean from previous tests.
	defer cleanUpJfrogHome()

	packages := clientTests.GetTestPackages("./...")
	// Exclude module to avoid loop
	packages = clientTests.ExcludeTestsPackage(packages, FrogbotModuleName)
	assert.NoError(t, clientTests.RunTests(packages, false))
}

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
