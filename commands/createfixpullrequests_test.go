package commands

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateFixPullRequests(t *testing.T) {
	testCreateFixPullRequests(t, "", "go-proj")
}

///      1.0         --> 1.0 ≤ x
///      (,1.0]      --> x ≤ 1.0
///      (,1.0)      --> x < 1.0
///      [1.0]       --> x == 1.0
///      (1.0,)      --> 1.0 < x
///      (1.0, 2.0)   --> 1.0 < x < 2.0
///      [1.0, 2.0]   --> 1.0 ≤ x ≤ 2.0
func TestParseVersionChangeString(t *testing.T) {
	tests := []struct {
		versionChangeString string
		expectedVersion     string
	}{
		{"1.2.3", "1.2.3"},
		{"[1.2.3]", "1.2.3"},
		{"[1.2.3, 2.0.0]", "1.2.3"},

		{"(,1.2.3]", ""},
		{"(,1.2.3)", ""},
		{"(1.2.3,)", ""},
		{"(1.2.3, 2.0.0)", ""},
	}

	for _, test := range tests {
		t.Run(test.versionChangeString, func(t *testing.T) {
			assert.Equal(t, test.expectedVersion, parseVersionChangeString(test.versionChangeString))
		})
	}
}

func TestGenerateFixBranchName(t *testing.T) {
	tests := []struct {
		baseBranch      string
		impactedPackage string
		fixVersion      string
		expectedName    string
	}{
		{"dev", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-d61bde82dc594e5ccc5a042fe224bf7c"},
		{"master", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-41405528994061bd108e3bbd4c039a03"},
		{"dev", "replace:colons:colons", "3.0.0", "frogbot-replace_colons_colons-89e555131b4a70a32fe9d9c44d6ff0fc"},
	}

	for _, test := range tests {
		t.Run(test.expectedName, func(t *testing.T) {
			branchName, err := generateFixBranchName(test.baseBranch, test.impactedPackage, test.fixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedName, branchName)
		})
	}
}

func testCreateFixPullRequests(t *testing.T, workingDirectory, projectName string) {
	// todo: add test
}
