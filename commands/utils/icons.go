package utils

import (
	"fmt"
	"strings"
)

func GetSeverityTag(iconName string) string {
	switch strings.ToLower(iconName) {
	case "critical":
		return getIconTag(criticalSeveritySource)
	case "high":
		return getIconTag(highSeveritySource)
	case "medium":
		return getIconTag(mediumSeveritySource)
	case "low":
		return getIconTag(lowSeveritySource)
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
