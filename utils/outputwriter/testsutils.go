package outputwriter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

	// The scan results link embeds a hash of the uploaded results and a timestamped artifact name,
	// so it changes on every run and cannot be stored in a golden file.
	// The simplified rendering must be matched first, since it contains the standard one.
	scanResultsLinkTitlePatterns = []*regexp.Regexp{
		scanResultsLinkTitlePattern(&SimplifiedOutput{}),
		scanResultsLinkTitlePattern(&StandardOutput{}),
	}
)

// scanResultsLinkTitlePattern matches the scan results link title as the given writer renders it,
// with any URL.
func scanResultsLinkTitlePattern(writer OutputWriter) *regexp.Regexp {
	const urlPlaceholder = "\x00"
	title := writer.MarkAsTitle(MarkAsLink(scanResultsLinkText, urlPlaceholder), 3)
	return regexp.MustCompile("\n" + strings.Replace(regexp.QuoteMeta(title), urlPlaceholder, `[^)]*`, 1))
}

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
	//#nosec G304 -- test helper; filePath is fixture paths supplied by tests.
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

// StripScanResultsLinkFromJsonBody removes the scan results platform link title from the body of a
// comment creation payload, so that the rest of the body can be compared against a golden file.
// It reports whether such a link was present.
func StripScanResultsLinkFromJsonBody(t *testing.T, payload []byte) (stripped []byte, found bool) {
	var bodyRes TestBodyResponse
	require.NoError(t, json.Unmarshal(payload, &bodyRes))
	for _, pattern := range scanResultsLinkTitlePatterns {
		if !pattern.MatchString(bodyRes.Body) {
			continue
		}
		bodyRes.Body = pattern.ReplaceAllString(bodyRes.Body, "")
		stripped, err := json.Marshal(bodyRes)
		require.NoError(t, err)
		return stripped, true
	}
	return payload, false
}
