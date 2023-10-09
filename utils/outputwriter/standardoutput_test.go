package outputwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandardOutputFlags(t *testing.T) {
	testCases := []struct {
		name         string
		entitled     bool
		showCaColumn bool
	}{
		{
			name:         "entitled",
			entitled:     true,
			showCaColumn: false,
		},
		{
			name:         "not entitled",
			entitled:     false,
			showCaColumn: false,
		},
		{
			name:         "entitled with ca column",
			entitled:     true,
			showCaColumn: true,
		},
		{
			name:         "not entitled with ca column",
			entitled:     false,
			showCaColumn: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			smo.SetJasOutputFlags(tc.entitled, tc.showCaColumn)
			assert.Equal(t, tc.entitled, smo.entitledForJas)
			assert.Equal(t, tc.showCaColumn, smo.showCaColumn)
			assert.Equal(t, tc.entitled, smo.IsEntitledForJas())
			assert.Equal(t, tc.showCaColumn, smo.IsShowingCaColumn())
		})
	}
}

func TestStandardSeparator(t *testing.T) {
	smo := &StandardOutput{}
	assert.Equal(t, "<br>", smo.Separator())
}

func TestStandardFormattedSeverity(t *testing.T) {
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
			expectedOutput: "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low",
		},
		{
			name:           "Not applicable severity",
			severity:       "Medium",
			applicability:  "Not Applicable",
			expectedOutput: "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableMedium.png)<br>  Medium",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			assert.Equal(t, tc.expectedOutput, smo.FormattedSeverity(tc.severity, tc.applicability))
		})
	}
}

func TestStandardImage(t *testing.T) {
	testCases := []struct {
		name           string
		source         ImageSource
		expectedOutput string
	}{
		{
			name:           "no vulnerability pr banner",
			source:         NoVulnerabilityPrBannerSource,
			expectedOutput: "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n",
		},
		{
			name:           "vulnerabilities pr banner",
			source:         VulnerabilitiesPrBannerSource,
			expectedOutput: "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n",
		},
		{
			name:           "no vulnerability mr banner",
			source:         NoVulnerabilityMrBannerSource,
			expectedOutput: "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerMR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n",
		},
		{
			name:           "vulnerabilities fix pr banner",
			source:         VulnerabilitiesFixPrBannerSource,
			expectedOutput: "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesFixBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n",
		},
		{
			name:           "vulnerabilities fix mr banner",
			source:         VulnerabilitiesFixMrBannerSource,
			expectedOutput: "<div align='center'>\n\n[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesFixBannerMR.png)](https://github.com/jfrog/frogbot#readme)\n\n</div>\n\n",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			assert.Equal(t, tc.expectedOutput, smo.Image(tc.source))
		})
	}
}

func TestStandardMarkInCenter(t *testing.T) {
	testCases := []struct {
		name           string
		content        string
		expectedOutput string
	}{
		{
			name:           "empty content",
			content:        "",
			expectedOutput: "\n<div align='center'>\n\n\n\n</div>",
		},
		{
			name:           "non empty content",
			content:        "content",
			expectedOutput: "\n<div align='center'>\n\ncontent\n\n</div>",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			assert.Equal(t, tc.expectedOutput, smo.MarkInCenter(tc.content))
		})
	}
}

func TestStandardMarkAsDetails(t *testing.T) {
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
			subTitleDepth:  1,
			content:        "",
			expectedOutput: "\n<details>\n<summary> <b></b> </summary>\n<br>\n\n\n</details>",
		},
		{
			name:           "empty content",
			summary:        "summary",
			subTitleDepth:  1,
			content:        "",
			expectedOutput: "\n<details>\n<summary> <b>summary</b> </summary>\n<br>\n\n\n</details>",
		},
		{
			name:           "empty summary",
			summary:        "",
			subTitleDepth:  1,
			content:        "content",
			expectedOutput: "\n<details>\n<summary> <b></b> </summary>\n<br>\ncontent\n\n</details>",
		},
		{
			name:           "Main details",
			summary:        "summary",
			subTitleDepth:  1,
			content:        "content",
			expectedOutput: "\n<details>\n<summary> <b>summary</b> </summary>\n<br>\ncontent\n\n</details>",
		},
		{
			name:           "Sub details",
			summary:        "summary",
			subTitleDepth:  2,
			content:        "content",
			expectedOutput: "\n<details>\n<summary> <b>summary</b> </summary>\n<br>\ncontent\n\n</details>",
		},
		{
			name:           "Sub sub details",
			summary:        "summary",
			subTitleDepth:  3,
			content:        "content",
			expectedOutput: "\n<details>\n<summary> <b>summary</b> </summary>\n<br>\ncontent\n\n</details>",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			assert.Equal(t, tc.expectedOutput, smo.MarkAsDetails(tc.summary, tc.subTitleDepth, tc.content))
		})
	}
}

func TestStandardMarkAsTitle(t *testing.T) {
	testCases := []struct {
		name           string
		title          string
		expectedOutput string
		subTitleDepth  int
	}{
		{
			name:           "empty",
			title:          "",
			subTitleDepth:  1,
			expectedOutput: "# ",
		},
		{
			name:           "Main title",
			title:          "title",
			subTitleDepth:  1,
			expectedOutput: "# title",
		},
		{
			name:           "Sub title",
			title:          "title",
			subTitleDepth:  2,
			expectedOutput: "## title",
		},
		{
			name:           "Sub sub title",
			title:          "title",
			subTitleDepth:  3,
			expectedOutput: "### title",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			assert.Equal(t, tc.expectedOutput, smo.MarkAsTitle(tc.title, tc.subTitleDepth))
		})
	}
}
