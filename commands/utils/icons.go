package utils

import (
	"fmt"
	"strings"
)

func GetSeverityTag(iconName string) string {
	switch strings.ToLower(iconName) {
	case "critical":
		getIconTag(criticalSeveritySource)
	case "high":
		getIconTag(highSeveritySource)
	case "medium":
		getIconTag(mediumSeveritySource)
	case "low":
		getIconTag(lowSeveritySource)
	}
	return ""
}

func GetNoVulnerabilitiesBanner() string {
	return getIconTag(NoVulnerabilityBannerSource)
}

func GetVulnerabilitiesBanner() string {
	return getIconTag(VulnerabilitiesBannerSource)
}

func getIconTag(imageSource imageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}
