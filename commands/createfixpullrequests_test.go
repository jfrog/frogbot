package commands

import (
	"github.com/sassoftware/go-rpmutils"
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

func testCreateFixPullRequests(t *testing.T, workingDirectory, projectName string) {
	// todo: add test
}
