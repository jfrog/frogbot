package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeverityTag(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/criticalSeverity.png)", GetSeverityTag("Critical"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png)", GetSeverityTag("HiGh"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/mediumSeverity.png)", GetSeverityTag("meDium"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/lowSeverity.png)", GetSeverityTag("low"))
	assert.Equal(t, "", GetSeverityTag("none"))
}

func TestGetVulnerabilitiesBanners(t *testing.T) {
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBanner.png)](https://github.com/jfrog/frogbot#frogbot)", GetBanner(NoVulnerabilityBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBanner.png)](https://github.com/jfrog/frogbot#frogbot)", GetBanner(VulnerabilitiesBannerSource))
}
