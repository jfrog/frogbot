package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeverityTag(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/criticalSeverity.png)", GetSeverityTag("Critical"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/highSeverity.png)", GetSeverityTag("HiGh"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/mediumSeverity.png)", GetSeverityTag("meDium"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/lowSeverity.png)", GetSeverityTag("low"))
	assert.Equal(t, "", GetSeverityTag("none"))
}

func TestGetVulnerabilitiesBanners(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/noVulnerabilityBanner.png)", GetNoVulnerabilitiesBanner())
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/dev/resources/vulnerabilitiesBanner.png)", GetVulnerabilitiesBanner())
}
