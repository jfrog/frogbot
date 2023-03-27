package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_GetMinimalFixVersionGeneric(t *testing.T) {
	type testCase struct {
		impactedPackageVersion string
		fixVersions            []string
		description            string
		expectedVersion        string
	}

	testCases := []testCase{
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{"0.9.0", "1.2.4", "1.2.6", "2.0.0"},
			description:            "Verify patch upgrade",
			expectedVersion:        "1.2.6",
		},
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{"0.9.0", "1.2.4", "2.2.6", "3.0.0"},
			description:            "Verify patch downgrade",
			expectedVersion:        "1.2.4",
		},
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{"0.9.0", "1.1.3", "1.4.2", "2.2.6"},
			description:            "Verify minor upgrade",
			expectedVersion:        "1.4.2",
		},
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{"0.9.0", "1.3.4", "2.2.6", "3.0.0"},
			description:            "Verify minor downgrade",
			expectedVersion:        "1.3.4",
		},
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{"0.9.0", "2.0.0", "3.0.0"},
			description:            "Verify major upgrade,none",
			expectedVersion:        "",
		},
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{"0.9.0"},
			description:            "Verify major downgrade,none",
			expectedVersion:        "",
		},
		{
			impactedPackageVersion: "1.2.5",
			fixVersions:            []string{},
			description:            "Verify no fixes",
			expectedVersion:        "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			actualOutput, err := getMinimalFixVersion(tc.impactedPackageVersion, tc.fixVersions)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedVersion, actualOutput)
		})
	}
}

// TODO address this test cases in the the above test
//func TestGetMinimalFixVersion(t *testing.T) {
//	impactedVersionPackage := "1.6.2"
//	fixVersions := []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}
//	assert.Equal(t, "1.6.22", getMinimalFixVersion(impactedVersionPackage, fixVersions))
//	impactedVersionPackageGo := "v" + impactedVersionPackage
//	assert.Equal(t, "1.6.22", getMinimalFixVersion(impactedVersionPackageGo, fixVersions))
//	impactedVersionPackage = "1.7.1"
//	assert.Equal(t, "", getMinimalFixVersion(impactedVersionPackage, fixVersions))
//}
