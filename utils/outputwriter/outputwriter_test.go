package outputwriter

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
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

// func testGetLicensesTableContent(t *testing.T, writer OutputWriter) {
// 	licenses := []formats.LicenseRow{}
// 	result := getLicensesTableContent(licenses, writer)
// 	expected := ""
// 	assert.Equal(t, expected, result)

// 	// Single license with components
// 	licenses = []formats.LicenseRow{
// 		{
// 			LicenseKey: "License1",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
// 				ImpactedDependencyName:    "Dep1",
// 				ImpactedDependencyVersion: "2.0",
// 			},
// 		},
// 	}
// 	result = getLicensesTableContent(licenses, writer)
// 	expected = "\n| License1 | Comp1 1.0 | Dep1 2.0 |"
// 	assert.Equal(t, expected, result)

// 	// Test case 3: Multiple licenses with components
// 	licenses = []formats.LicenseRow{
// 		{
// 			LicenseKey: "License1",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				Components:                []formats.ComponentRow{{Name: "Comp1", Version: "1.0"}},
// 				ImpactedDependencyName:    "Dep1",
// 				ImpactedDependencyVersion: "2.0",
// 			},
// 		},
// 		{
// 			LicenseKey: "License2",
// 			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
// 				Components:                []formats.ComponentRow{{Name: "Comp2", Version: "2.0"}},
// 				ImpactedDependencyName:    "Dep2",
// 				ImpactedDependencyVersion: "3.0",
// 			},
// 		},
// 	}
// 	result = getLicensesTableContent(licenses, writer)
// 	expected = "\n| License1 | Comp1 1.0 | Dep1 2.0 |\n| License2 | Comp2 2.0 | Dep2 3.0 |"
// 	assert.Equal(t, expected, result)
// }

func TestMarkAsQuote(t *testing.T) {
	testCases := []struct {
		input          string
		expectedOutput string
	}{
		{
			input:          "",
			expectedOutput: "``",
		},
		{
			input:          "quote",
			expectedOutput: "`quote`",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, MarkAsQuote(tc.input))
	}
}

func TestMarkAsCodeSnippet(t *testing.T) {
	testCases := []struct {
		input          string
		expectedOutput string
	}{
		{
			input:          "",
			expectedOutput: "```\n\n```",
		},
		{
			input:          "snippet",
			expectedOutput: "```\nsnippet\n```",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, MarkAsCodeSnippet(tc.input))
	}
}

func TestGetLocationDescription(t *testing.T) {
	testCases := []struct {
		input          formats.Location
		expectedOutput string
	}{
		{
			input: formats.Location{
				File:      "file1",
				StartLine: 1,
				Snippet:   "snippet",
			},
			expectedOutput: "\n```\nsnippet\n```\nat `file1` (line 1)\n",
		},
		{
			input: formats.Location{
				File:      "dir/other-dir/file1",
				StartLine: 134,
				Snippet:   "clientTestUtils.ChangeDirAndAssert(t, prevWd)",
			},
			expectedOutput: "\n```\nclientTestUtils.ChangeDirAndAssert(t, prevWd)\n```\nat `dir/other-dir/file1` (line 134)\n",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, getFallbackCommentLocationDescription(tc.input))
	}
}

func TestGetJasMarkdownDescription(t *testing.T) {
	testCases := []struct {
		severity       string
		finding        string
		expectedOutput string
	}{
		{
			severity:       "High",
			finding:        "finding",
			expectedOutput: "| Severity | Finding |\n| :--------------: | :---: |\n| High | finding |",
		},
		{
			severity:       "Low",
			finding:        "finding (other)",
			expectedOutput: "| Severity | Finding |\n| :--------------: | :---: |\n| Low | finding (other) |",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, GetJasMarkdownDescription(tc.severity, tc.finding))
	}
}

func TestGetApplicabilityMarkdownDescription(t *testing.T) {
	testCases := []struct {
		severity           string
		cve                string
		impactedDependency string
		finding            string
		expectedOutput     string
	}{
		{
			severity:           "High",
			cve:                "CVE-100-234",
			impactedDependency: "dependency:1.0.0",
			finding:            "applicable finding",
			expectedOutput:     "| Severity | Impacted Dependency | Finding | CVE |\n| :--------------: | :---: | :---: | :---: |\n| High | dependency:1.0.0 | applicable finding | CVE-100-234 |",
		},
		{
			severity:           "Low",
			cve:                "CVE-222-233",
			impactedDependency: "dependency:3.4.1",
			finding:            "applicable finding (diff)",
			expectedOutput:     "| Severity | Impacted Dependency | Finding | CVE |\n| :--------------: | :---: | :---: | :---: |\n| Low | dependency:3.4.1 | applicable finding (diff) | CVE-222-233 |",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, GetApplicabilityMarkdownDescription(tc.severity, tc.cve, tc.impactedDependency, tc.finding))
	}
}

func TestGenerateReviewCommentContent(t *testing.T) {
	writer := &StandardOutput{}
	content := "some review content"
	expectedOutput := "\n\n[comment]: <> (FrogbotReviewComment)\nsome review content" + Footer(writer)
	assert.Equal(t, expectedOutput, GenerateReviewCommentContent(content, writer))
}

func TestGetFallbackReviewCommentContent(t *testing.T) {
	writer := &StandardOutput{}
	content := "some review content"
	location := formats.Location{
		File:        "file",
		StartLine:   1,
		StartColumn: 2,
		EndLine:     3,
		EndColumn:   4,
		Snippet:     "snippet",
	}
	expectedOutput := "\n\n[comment]: <> (FrogbotReviewComment)\n\n```\nsnippet\n```\nat `file` (line 1)\nsome review content" + Footer(writer)
	assert.Equal(t, expectedOutput, GetFallbackReviewCommentContent(content, location, writer))
}
