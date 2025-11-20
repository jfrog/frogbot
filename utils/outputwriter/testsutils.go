package outputwriter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// Used for tests that are outside the outputwriter package.
	TestMessagesDir = filepath.Join("..", "testdata", "messages")
	// Used for tests that are inside the outputwriter package.
	testMessagesDir       = filepath.Join("..", TestMessagesDir)
	testReviewCommentDir  = filepath.Join(testMessagesDir, "reviewcomment")
	testSummaryCommentDir = filepath.Join(testMessagesDir, "summarycomment")
)

type OutputTestCase struct {
	name               string
	writer             OutputWriter
	expectedOutputPath []string
	expectedOutput     []string
}

type TestBodyResponse struct {
	Body string `json:"body"`
}

func GetExpectedTestCaseOutput(t *testing.T, testCase OutputTestCase) []string {
	if len(testCase.expectedOutputPath) > 0 {
		content := make([]string, len(testCase.expectedOutputPath))
		for i, path := range testCase.expectedOutputPath {
			content[i] = GetOutputFromFile(t, path)
		}
		return content
	}
	return testCase.expectedOutput
}

func GetExpectedTestOutput(t *testing.T, testCase OutputTestCase) string {
	out := GetExpectedTestCaseOutput(t, testCase)
	require.Len(t, out, 1)
	return out[0]
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
