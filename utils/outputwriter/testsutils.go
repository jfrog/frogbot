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
	TestMessagesDir = filepath.Join("..", "testdata", "messages")

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
	// Replace single quotes with double quotes
	// jsonStr := strings.ReplaceAll(string(bytes), "<", "\u003c")
	// jsonStr = strings.ReplaceAll(string(bytes), ">", "\u003e")
	// jsonStr = strings.ReplaceAll(string(bytes), "\"", "'")
	// jsonStr := html.EscapeString(string(bytes))
	
	// return []byte(strings.ReplaceAll(string(bytes), "align=\"center\"", "align='center'"))
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
