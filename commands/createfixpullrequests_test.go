package commands

import (
	"github.com/sassoftware/go-rpmutils"
	"testing"
)

func TestCreateFixPullRequests(t *testing.T) {
	testCreateFixPullRequests(t, "", "go-proj")
}

func testCreateFixPullRequests(t *testing.T, workingDirectory, projectName string) {
	// todo: add test

	// add vulnerable dependency
	rpmutils.Vercmp("", "")
}
