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
