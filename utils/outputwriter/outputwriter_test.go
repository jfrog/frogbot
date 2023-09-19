package outputwriter

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMarkdownComment(t *testing.T) {
	text := ""
	result := MarkdownComment(text)
	expected := "\n\n[comment]: <> ()\n"
	assert.Equal(t, expected, result)

	text = "This is a comment"
	result = MarkdownComment(text)
	expected = "\n\n[comment]: <> (This is a comment)\n"
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
