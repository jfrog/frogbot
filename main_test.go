package main

import (
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var IntegrationTestPackages = []string{
	"github.com/jfrog/frogbot/v2",
	"github.com/jfrog/frogbot/v2/scanrepository",
	"github.com/jfrog/frogbot/v2/scanpullrequest",
	"github.com/jfrog/frogbot/v2/packagehandlers",
}

func TestUnitTests(t *testing.T) {
	packages := clientTests.GetTestPackages("./...")
	for _, integrationPackage := range IntegrationTestPackages {
		packages = clientTests.ExcludeTestsPackage(packages, integrationPackage)
	}
	log.Info("Running Unit tests on the following packages:\n", strings.Join(packages, "\n"))
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
