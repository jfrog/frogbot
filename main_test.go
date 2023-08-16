package main

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var IntegrationTestPackages = []string{
	"github.com/jfrog/frogbot/commands/scanrepository",
	"github.com/jfrog/frogbot/commands/scanpullrequest",
}

func TestUnitTests(t *testing.T) {
	packages := clientTests.GetTestPackages("./...")
	for _, integrationPackage := range IntegrationTestPackages {
		packages = clientTests.ExcludeTestsPackage(packages, integrationPackage)
	}
	assert.NoError(t, clientTests.RunTests(packages, false))
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
