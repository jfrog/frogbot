package packagehandlers

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFixVersionInfo_UpdateFixVersion(t *testing.T) {
	type testCase struct {
		fixVersionInfo FixVersionInfo
		newFixVersion  string
		expectedOutput string
	}

	testCases := []testCase{
		{fixVersionInfo: FixVersionInfo{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.2.4", expectedOutput: "1.2.4"},
		{fixVersionInfo: FixVersionInfo{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.0.4", expectedOutput: "1.2.3"},
	}

	for _, tc := range testCases {
		t.Run(tc.expectedOutput, func(t *testing.T) {
			tc.fixVersionInfo.UpdateFixVersion(tc.newFixVersion)
			assert.Equal(t, tc.expectedOutput, tc.fixVersionInfo.FixVersion)
		})
	}
}
