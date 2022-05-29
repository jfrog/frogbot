package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeverityTag(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/criticalSeverity.png)<br>", GetSeverityTag("Critical"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png)<br>", GetSeverityTag("HiGh"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/mediumSeverity.png)<br>", GetSeverityTag("meDium"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/lowSeverity.png)<br>", GetSeverityTag("low"))
	assert.Equal(t, "", GetSeverityTag("none"))
}

func TestGetEmojiSeverityTag(t *testing.T) {
	assert.Equal(t, "💀 ", GetEmojiSeverityTag("Critical"))
	assert.Equal(t, "🔥 ", GetEmojiSeverityTag("HiGh"))
	assert.Equal(t, "🎃 ", GetEmojiSeverityTag("meDium"))
	assert.Equal(t, "👻 ", GetEmojiSeverityTag("low"))
	assert.Equal(t, "", GetEmojiSeverityTag("none"))
}

func TestGetVulnerabilitiesBanners(t *testing.T) {
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBanner.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(NoVulnerabilityBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBanner.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(VulnerabilitiesBannerSource))
}

func TestGetSimplifiedTitle(t *testing.T) {
	assert.Equal(t, "🐸 Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n", GetSimplifiedTitle(NoVulnerabilityBannerSource))
	assert.Equal(t, "🐸 Frogbot scanned this pull request and found the issues blow: \n", GetSimplifiedTitle(VulnerabilitiesBannerSource))
	assert.Equal(t, "", GetSimplifiedTitle("none"))
}
