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
		{vcsutils.GitHub, "applicable", "$\\color{red}{\\textsf{applicable}}$"},
		{vcsutils.GitHub, "not applicable", "$\\color{green}{\\textsf{not applicable}}$"},
		{vcsutils.GitHub, "undetermined", "$\\color{blue}{\\textsf{undetermined}}$"},

		// Test cases for GitLab as gitProvider
		{vcsutils.GitLab, "applicable", "$\\color{red}{\\textsf{applicable}}$"},
		{vcsutils.GitLab, "not applicable", "$\\color{green}{\\textsf{not applicable}}$"},
		{vcsutils.GitLab, "undetermined", "$\\color{blue}{\\textsf{undetermined}}$"},

		// Test cases for AzureRepos as gitProvider
		{vcsutils.AzureRepos, "applicable", "<span style=\"color: red;\">applicable</span>"},
		{vcsutils.AzureRepos, "not applicable", "<span style=\"color: green;\">not applicable</span>"},
		{vcsutils.AzureRepos, "undetermined", "<span style=\"color: blue;\">undetermined</span>"},

		{vcsutils.BitbucketServer, "applicable", "**APPLICABLE**"},
		{vcsutils.BitbucketServer, "not applicable", "**NOT APPLICABLE**"},
		{vcsutils.BitbucketServer, "undetermined", "**UNDETERMINED**"},
	}

	for _, test := range tests {
		result := formattedApplicabilityText(test.text, test.provider)
		assert.Equal(t, result, test.expected)
	}
}
