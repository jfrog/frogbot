package outputwriter

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetAggregatedPullRequestTitle(t *testing.T) {
	tests := []struct {
		tech     coreutils.Technology
		expected string
	}{
		{tech: "", expected: "[🐸 Frogbot] Update dependencies"},
		{tech: coreutils.Maven, expected: "[🐸 Frogbot] Update Maven dependencies"},
		{tech: coreutils.Gradle, expected: "[🐸 Frogbot] Update Gradle dependencies"},
		{tech: coreutils.Npm, expected: "[🐸 Frogbot] Update npm dependencies"},
		{tech: coreutils.Yarn, expected: "[🐸 Frogbot] Update Yarn dependencies"},
	}

	for _, test := range tests {
		title := GetAggregatedPullRequestTitle(test.tech)
		assert.Equal(t, test.expected, title)
	}
}

func TestMarkdownComment(t *testing.T) {
	text := ""
	result := MarkdownComment(text)
	expected := "\n[comment]: <> ()\n"
	assert.Equal(t, expected, result)

	text = "This is a comment"
	result = MarkdownComment(text)
	expected = "\n[comment]: <> (This is a comment)\n"
	assert.Equal(t, expected, result)
}

func testGetLicensesTableContent(t *testing.T, writer OutputWriter) {
	licenses := []formats.LicenseRow{}
	result := getLicensesTableContent(licenses, writer)
	expected := ""
	assert.Equal(t, expected, result)

	// Single license with components
	licenses = []formats.LicenseRow{
		{
			LicenseKey: "License1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
				ImpactedDependencyName:    "Dep1",
				ImpactedDependencyVersion: "2.0",
			},
		},
	}
	result = getLicensesTableContent(licenses, writer)
	expected = "\n| License1 | Comp1 1.0 | Dep1 2.0 |"
	assert.Equal(t, expected, result)

	// Test case 3: Multiple licenses with components
	licenses = []formats.LicenseRow{
		{
			LicenseKey: "License1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
				ImpactedDependencyName:    "Dep1",
				ImpactedDependencyVersion: "2.0",
			},
		},
		{
			LicenseKey: "License2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				Components:                []formats.ComponentRow{{Name: "Comp2", Version: "2.0"}},
				ImpactedDependencyName:    "Dep2",
				ImpactedDependencyVersion: "3.0",
			},
		},
	}
	result = getLicensesTableContent(licenses, writer)
	expected = "\n| License1 | Comp1 1.0 | Dep1 2.0 |\n| License2 | Comp2 2.0 | Dep2 3.0 |"
	assert.Equal(t, expected, result)
}
