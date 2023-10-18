package outputwriter

import (
	"strings"
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

func TestMarkAsBold(t *testing.T) {
	testCases := []struct {
		input          string
		expectedOutput string
	}{
		{
			input:          "",
			expectedOutput: "****",
		},
		{
			input:          "bold",
			expectedOutput: "**bold**",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, MarkAsBold(tc.input))
	}
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

func TestMarkAsLink(t *testing.T) {
	testCases := []struct {
		content        string
		url            string
		expectedOutput string
	}{
		{
			content:        "",
			url:            "",
			expectedOutput: "[]()",
		},
		{
			content:        "content",
			url:            "",
			expectedOutput: "[content]()",
		},
		{
			content:        "",
			url:            "url",
			expectedOutput: "[](url)",
		},
		{
			content:        "content",
			url:            "url",
			expectedOutput: "[content](url)",
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expectedOutput, MarkAsLink(tc.content, tc.url))
	}
}

func TestSectionDivider(t *testing.T) {
	assert.Equal(t, "\n---", SectionDivider())
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

func TestWriteContent(t *testing.T) {
	testCases := []struct {
		expectedOutput string
		input          []string
	}{
		{
			input:          []string{},
			expectedOutput: "",
		},
		{
			input:          []string{"content"},
			expectedOutput: "\ncontent",
		},
		{
			input:          []string{"contentA", "contentB", "contentC"},
			expectedOutput: "\ncontentA\ncontentB\ncontentC",
		},
	}
	for _, tc := range testCases {
		builder := &strings.Builder{}
		WriteContent(builder, tc.input...)
		assert.Equal(t, tc.expectedOutput, builder.String())
	}
}
