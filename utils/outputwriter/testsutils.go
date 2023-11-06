package outputwriter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	// Used for tests that are outside the outputwriter package.
	TestMessagesDir       = filepath.Join("..", "testdata", "messages")
	TestSummaryCommentDir = filepath.Join(TestMessagesDir, "summarycomment")
	// Used for tests that are inside the outputwriter package.
	testMessagesDir       = filepath.Join("..", TestMessagesDir)
	testReviewCommentDir  = filepath.Join(testMessagesDir, "reviewcomment")
	testSummaryCommentDir = filepath.Join(testMessagesDir, "summarycomment")
)

type OutputTestCase struct {
	name               string
	writer             OutputWriter
	expectedOutputPath string
	expectedOutput     string
}

type TestBodyResponse struct {
	Body string `json:"body"`
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

func GetJsonBodyOutputFromFile(t *testing.T, filePath string) []byte {
	bodyRes := TestBodyResponse{Body: GetOutputFromFile(t, filePath)}
	bytes, err := json.Marshal(bodyRes)
	assert.NoError(t, err)
	return bytes
}

func GetPRSummaryContentNoIssues(t *testing.T, summaryTestDir string, entitled, simplified bool) string {
	dataPath := filepath.Join(summaryTestDir, "structure")
	if simplified {
		if entitled {
			dataPath = filepath.Join(dataPath, "summary_comment_no_issues_simplified_entitled.md")
		} else {
			dataPath = filepath.Join(dataPath, "summary_comment_no_issues_simplified_not_entitled.md")
		}
	} else {
		if entitled {
			dataPath = filepath.Join(dataPath, "summary_comment_no_issues_pr_entitled.md")
		} else {
			dataPath = filepath.Join(dataPath, "summary_comment_no_issues_pr_not_entitled.md")
		}
	}
	return GetOutputFromFile(t, dataPath)
}
