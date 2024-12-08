package outputwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleOutputFlags(t *testing.T) {
	testCases := []struct {
		name         string
		entitled     bool
		showCaColumn bool
	}{
		{name: "entitled", entitled: true, showCaColumn: false},
		{name: "not entitled", entitled: false, showCaColumn: false},
		{name: "entitled with ca column", entitled: true, showCaColumn: true},
		{name: "not entitled with ca column", entitled: false, showCaColumn: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			smo.SetJasOutputFlags(tc.entitled, tc.showCaColumn)
			assert.Equal(t, tc.entitled, smo.entitledForJas)
			assert.Equal(t, tc.showCaColumn, smo.showCaColumn)
			assert.Equal(t, tc.entitled, smo.IsEntitledForJas())
			assert.Equal(t, tc.showCaColumn, smo.IsShowingCaColumn())
		})
	}
}

func TestSimpleSeparator(t *testing.T) {
	smo := &SimplifiedOutput{}
	assert.Equal(t, ", ", smo.Separator())
}

func TestSimpleFormattedSeverity(t *testing.T) {
	testCases := []struct {
		name           string
		severity       string
		applicability  string
		expectedOutput string
	}{
		{
			name:           "Applicable severity",
			severity:       "Low",
			applicability:  "Applicable",
			expectedOutput: "Low",
		},
		{
			name:           "Not applicable severity",
			severity:       "Medium",
			applicability:  "Not Applicable",
			expectedOutput: "Medium",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			assert.Equal(t, tc.expectedOutput, smo.FormattedSeverity(tc.severity, tc.applicability))
		})
	}
}

func TestSimpleImage(t *testing.T) {
	testCases := []struct {
		name           string
		source         ImageSource
		expectedOutput string
	}{
		{
			name:           "no vulnerability pr banner",
			source:         NoVulnerabilityPrBannerSource,
			expectedOutput: "**👍 Frogbot scanned this pull request and did not find any new security issues.**",
		},
		{
			name:           "vulnerabilities pr banner",
			source:         VulnerabilitiesPrBannerSource,
			expectedOutput: "**🚨 Frogbot scanned this pull request and found the below:**",
		},
		{
			name:           "vulnerabilities fix pr banner",
			source:         VulnerabilitiesFixPrBannerSource,
			expectedOutput: "**🚨 This automated pull request was created by Frogbot and fixes the below:**",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			assert.Equal(t, tc.expectedOutput, smo.Image(tc.source))
		})
	}
}

func TestSimpleMarkInCenter(t *testing.T) {
	testCases := []struct {
		name           string
		content        string
		expectedOutput string
	}{
		{
			name:           "empty content",
			content:        "",
			expectedOutput: "",
		},
		{
			name:           "non empty content",
			content:        "content",
			expectedOutput: "content",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			assert.Equal(t, tc.expectedOutput, smo.MarkInCenter(tc.content))
		})
	}
}

func TestSimpleMarkAsDetails(t *testing.T) {
	testCases := []struct {
		name           string
		summary        string
		content        string
		expectedOutput string
		subTitleDepth  int
	}{
		{
			name:           "empty",
			summary:        "",
			subTitleDepth:  0,
			content:        "",
			expectedOutput: "\n---\n\n\n---\n",
		},
		{
			name:           "empty content",
			summary:        "summary",
			subTitleDepth:  1,
			content:        "",
			expectedOutput: "\n---\n# summary\n\n---\n",
		},
		{
			name:           "empty summary",
			summary:        "",
			subTitleDepth:  1,
			content:        "content",
			expectedOutput: "\n---\n# \n\n---\ncontent",
		},
		{
			name:           "Main details",
			summary:        "summary",
			subTitleDepth:  1,
			content:        "content",
			expectedOutput: "\n---\n# summary\n\n---\ncontent",
		},
		{
			name:           "Sub details",
			summary:        "summary",
			subTitleDepth:  2,
			content:        "content",
			expectedOutput: "\n---\n## summary\n\n---\ncontent",
		},
		{
			name:           "Sub sub details",
			summary:        "summary",
			subTitleDepth:  3,
			content:        "content",
			expectedOutput: "\n---\n### summary\n\n---\ncontent",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			assert.Equal(t, tc.expectedOutput, smo.MarkAsDetails(tc.summary, tc.subTitleDepth, tc.content))
		})
	}
}

func TestSimpleMarkAsTitle(t *testing.T) {
	testCases := []struct {
		name           string
		title          string
		expectedOutput string
		subTitleDepth  int
	}{
		{
			name:           "empty",
			title:          "",
			subTitleDepth:  0,
			expectedOutput: "\n---\n\n\n---",
		},
		{
			name:           "Main title",
			title:          "title",
			subTitleDepth:  1,
			expectedOutput: "\n---\n# title\n\n---",
		},
		{
			name:           "Sub title",
			title:          "title",
			subTitleDepth:  2,
			expectedOutput: "\n---\n## title\n\n---",
		},
		{
			name:           "Sub sub title",
			title:          "title",
			subTitleDepth:  3,
			expectedOutput: "\n---\n### title\n\n---",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			assert.Equal(t, tc.expectedOutput, smo.MarkAsTitle(tc.title, tc.subTitleDepth))
		})
	}
}
