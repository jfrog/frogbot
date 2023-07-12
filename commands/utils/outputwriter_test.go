package utils

import (
	"github.com/jfrog/froggit-go/vcsutils"
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
		{vcsutils.GitHub, "applicable", "**APPLICABLE**"},
		{vcsutils.GitHub, "not applicable", "**NOT APPLICABLE**"},
		{vcsutils.GitHub, "undetermined", "**UNDETERMINED**"},

		// Test cases for GitLab as gitProvider
		{vcsutils.GitLab, "applicable", "**APPLICABLE**"},
		{vcsutils.GitLab, "not applicable", "**NOT APPLICABLE**"},
		{vcsutils.GitLab, "undetermined", "**UNDETERMINED**"},

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
