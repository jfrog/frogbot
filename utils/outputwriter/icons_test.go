package outputwriter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSmallSeverityTag(t *testing.T) {
	assert.Equal(t, "<img src=\"https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallCritical.svg\" alt=\"\"/>", getSmallSeverityTag("Critical"))
	assert.Equal(t, "<img src=\"https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallHigh.svg\" alt=\"\"/>", getSmallSeverityTag("HiGh"))
	assert.Equal(t, "<img src=\"https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallMedium.svg\" alt=\"\"/>", getSmallSeverityTag("meDium"))
	assert.Equal(t, "<img src=\"https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallLow.svg\" alt=\"\"/>", getSmallSeverityTag("low"))
	assert.Equal(t, "<img src=\"https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallUnknown.svg\" alt=\"\"/>", getSmallSeverityTag("none"))
}

func TestGetSeverityTag(t *testing.T) {
	assert.Equal(t, "![critical](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>", getSeverityTag("Critical", "Undetermined"))
	assert.Equal(t, "![high](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>", getSeverityTag("HiGh", "Undetermined"))
	assert.Equal(t, "![medium](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>", getSeverityTag("meDium", "Undetermined"))
	assert.Equal(t, "![low](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>", getSeverityTag("low", "Applicable"))
	assert.Equal(t, "![unknown](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableUnknownSeverity.png)<br>", getSeverityTag("none", "Applicable"))
}

func TestGetSeverityTagNotApplicable(t *testing.T) {
	assert.Equal(t, "![critical (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>", getSeverityTag("Critical", "Not Applicable"))
	assert.Equal(t, "![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>", getSeverityTag("HiGh", "Not Applicable"))
	assert.Equal(t, "![medium (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableMedium.png)<br>", getSeverityTag("meDium", "Not Applicable"))
	assert.Equal(t, "![low (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableLow.png)<br>", getSeverityTag("low", "Not Applicable"))
	assert.Equal(t, "![unknown (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableUnknown.png)<br>", getSeverityTag("none", "Not Applicable"))
}

func TestGetVulnerabilitiesBanners(t *testing.T) {
	assert.Equal(t, "<div align='center'>\n\n[![👍 Frogbot scanned this pull request and did not find any new security issues.](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot)\n\n</div>\n", GetBanner(NoVulnerabilityPrBannerSource))
	assert.Equal(t, "<div align='center'>\n\n[![👍 Frogbot scanned this merge request and did not find any new security issues.](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerMR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot)\n\n</div>\n", GetBanner(NoVulnerabilityMrBannerSource))
	assert.Equal(t, "<div align='center'>\n\n[![🚨 Frogbot scanned this pull request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot)\n\n</div>\n", GetBanner(VulnerabilitiesPrBannerSource))
	assert.Equal(t, "<div align='center'>\n\n[![🚨 Frogbot scanned this merge request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot)\n\n</div>\n", GetBanner(VulnerabilitiesMrBannerSource))
	assert.Equal(t, "<div align='center'>\n\n[![🚨 This automated pull request was created by Frogbot and fixes the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesFixBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot)\n\n</div>\n", GetBanner(VulnerabilitiesFixPrBannerSource))
	assert.Equal(t, "<div align='center'>\n\n[![🚨 This automated merge request was created by Frogbot and fixes the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesFixBannerMR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot)\n\n</div>\n", GetBanner(VulnerabilitiesFixMrBannerSource))
}

func TestGetSimplifiedTitle(t *testing.T) {
	assert.Equal(t, "👍 Frogbot scanned this pull request and did not find any new security issues.", GetSimplifiedTitle(NoVulnerabilityPrBannerSource))
	assert.Equal(t, "🚨 Frogbot scanned this pull request and found the below:", GetSimplifiedTitle(VulnerabilitiesPrBannerSource))
	assert.Equal(t, "🚨 This automated pull request was created by Frogbot and fixes the below:", GetSimplifiedTitle(VulnerabilitiesFixPrBannerSource))
	assert.Equal(t, "", GetSimplifiedTitle("none"))
}
