package outputwriter

import (
	"testing"

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
