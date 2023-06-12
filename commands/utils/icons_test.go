package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeverityTag(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/criticalSeverity.png)<br>", GetSeverityTag("Critical", "Undetermined"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png)<br>", GetSeverityTag("HiGh", "Undetermined"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/mediumSeverity.png)<br>", GetSeverityTag("meDium", "Undetermined"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/lowSeverity.png)<br>", GetSeverityTag("low", "Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/unknownSeverity.png)<br>", GetSeverityTag("none", "Applicable"))
}

func TestGetSeverityTagNotApplicable(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableCritical.png)<br>", GetSeverityTag("Critical", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableHigh.png)<br>", GetSeverityTag("HiGh", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableMedium.png)<br>", GetSeverityTag("meDium", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableLow.png)<br>", GetSeverityTag("low", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableUnknown.png)<br>", GetSeverityTag("none", "Not Applicable"))
}

func TestGetVulnerabilitiesBanners(t *testing.T) {
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBanner.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(NoVulnerabilityBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBanner.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(VulnerabilitiesBannerSource))
}

func TestGetSimplifiedTitle(t *testing.T) {
	assert.Equal(t, "**👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies.** \n", GetSimplifiedTitle(NoVulnerabilityBannerSource))
	assert.Equal(t, "**🚨 Frogbot scanned this pull request and found the below:**\n", GetSimplifiedTitle(VulnerabilitiesBannerSource))
	assert.Equal(t, "", GetSimplifiedTitle("none"))
}
