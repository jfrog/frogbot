package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
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

// Specific for Maven
func TestShouldFixMavenVulnerability(t *testing.T) {
	// TODO implement me
}

// Specific for Go
func TestTrimVersionPrefix(t *testing.T) {
	type testCase struct {
		impactedPackageVersion *formats.VulnerabilityOrViolationRow
		original               string
		expectedVersion        string
		description            string
	}

	testCases := []testCase{
		{
			impactedPackageVersion: &formats.VulnerabilityOrViolationRow{
				ImpactedDependencyVersion: "v1.2.5",
			},
			original:        "v1.2.5",
			expectedVersion: "1.2.5",
			description:     "validates remove prefix",
		},
		{
			impactedPackageVersion: &formats.VulnerabilityOrViolationRow{
				ImpactedDependencyVersion: "1.3.555",
			},
			original:        "v1.3.555",
			expectedVersion: "1.3.555",
			description:     "validates no prefix removal",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			trimVersionPrefix(tc.impactedPackageVersion)
			assert.Equal(t, tc.impactedPackageVersion.ImpactedDependencyVersion, tc.expectedVersion)
		})
	}
}
