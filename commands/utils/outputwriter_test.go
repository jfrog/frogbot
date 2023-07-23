package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
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
