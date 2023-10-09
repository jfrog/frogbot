package outputwriter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	TestMessagesDir       = filepath.Join("..", "testdata", "messages")

	testMessagesDir       = filepath.Join("..", TestMessagesDir)
	testReviewCommentDir  = filepath.Join(testMessagesDir, "reviewcomment")
	testSummaryCommentDir = filepath.Join(testMessagesDir, "summarycomment")

	TestSummaryCommentDir = filepath.Join(TestMessagesDir, "summarycomment")
)

type OutputTestCase struct {
	name               string
	writer             OutputWriter
	expectedOutputPath string
	expectedOutput     string
}

func GetExpectedTestOutput(t *testing.T, testCase OutputTestCase) string {
	if testCase.expectedOutputPath != "" {
		return GetOutputFromFile(t, testCase.expectedOutputPath)
	}
	return testCase.expectedOutput
}

func GetOutputFromFile(t *testing.T, filePath string) string {
	content, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}

func GetPRSummaryContentNoIssues(t *testing.T, entitled, simplified bool) string {
	dataPath := filepath.Join(TestSummaryCommentDir, "structure")
	if simplified {
		if entitled {
			dataPath = filepath.Join(dataPath, "summary_comment_simplified_no_issues_entitled.md")
		} else {
			dataPath = filepath.Join(dataPath, "summary_comment_simplified_no_issues_not_entitled.md")
		}
	} else {
		if entitled {
			dataPath = filepath.Join(dataPath, "summary_comment_pr_no_issues_entitled.md")
		} else {
			dataPath = filepath.Join(dataPath, "summary_comment_pr_no_issues_not_entitled.md")
		}
	}
	return GetOutputFromFile(t, dataPath)
}