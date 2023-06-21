package utils

import (
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFormattedApplicabilityText(t *testing.T) {
	tests := []struct {
		provider vcsutils.VcsProvider
		text     string
		expected string
	}{
		// Test cases for GitHub as gitProvider
		{vcsutils.GitHub, "applicable", "$\\color{#FF7377}{\\textsf{applicable}}$"},
		{vcsutils.GitHub, "not applicable", "$\\color{#3CB371}{\\textsf{not applicable}}$"},
		{vcsutils.GitHub, "undetermined", "$\\color{}{\\textsf{undetermined}}$"},

		// Test cases for GitLab as gitProvider
		{vcsutils.GitLab, "applicable", "$\\color{#FF7377}{\\textsf{applicable}}$"},
		{vcsutils.GitLab, "not applicable", "$\\color{#3CB371}{\\textsf{not applicable}}$"},
		{vcsutils.GitLab, "undetermined", "$\\color{}{\\textsf{undetermined}}$"},

		// Test cases for AzureRepos as gitProvider
		{vcsutils.AzureRepos, "applicable", "<span style=\"color: #FF7377;\">applicable</span>"},
		{vcsutils.AzureRepos, "not applicable", "<span style=\"color: #3CB371;\">not applicable</span>"},
		{vcsutils.AzureRepos, "undetermined", "<span style=\"color: ;\">undetermined</span>"},

		{vcsutils.BitbucketServer, "applicable", "**APPLICABLE**"},
		{vcsutils.BitbucketServer, "not applicable", "**NOT APPLICABLE**"},
		{vcsutils.BitbucketServer, "undetermined", "**UNDETERMINED**"},
	}

	for _, test := range tests {
		result := formattedApplicabilityText(test.text, test.provider)
		assert.Equal(t, result, test.expected)
	}
}

func TestGetIacTableContent(t *testing.T) {
	testCases := []struct {
		name           string
		iacRows        []formats.IacSecretsRow
		expectedOutput string
	}{
		{
			name:           "Empty IAC rows",
			iacRows:        []formats.IacSecretsRow{},
			expectedOutput: "",
		},
		{
			name: "Single IAC row",
			iacRows: []formats.IacSecretsRow{
				{
					Severity:         "Medium",
					SeverityNumValue: 2,
					File:             "file1",
					LineColumn:       "1:10",
					Text:             "Public access to MySQL was detected",
					Type:             "azure_mysql_no_public",
				},
			},
			expectedOutput: "\n| Medium | file1 | 1:10 | Public access to MySQL was detected | azure_mysql_no_public |",
		},
		{
			name: "Multiple IAC rows",
			iacRows: []formats.IacSecretsRow{
				{
					Severity:         "High",
					SeverityNumValue: 3,
					File:             "file1",
					LineColumn:       "1:10",
					Text:             "Public access to MySQL was detected",
					Type:             "azure_mysql_no_public",
				},
				{
					Severity:         "Medium",
					SeverityNumValue: 2,
					File:             "file2",
					LineColumn:       "2:5",
					Text:             "Public access to MySQL was detected",
					Type:             "azure_mysql_no_public",
				},
			},
			expectedOutput: "\n| High | file1 | 1:10 | Public access to MySQL was detected | azure_mysql_no_public |\n| Medium | file2 | 2:5 | Public access to MySQL was detected | azure_mysql_no_public |",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getIacTableContent(tc.iacRows)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
