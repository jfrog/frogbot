package utils

import (
	"fmt"
	"strings"
)

func GetSeverityTag(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return getIconTag(criticalSeveritySource) + "<br>"
	case "high":
		return getIconTag(highSeveritySource) + "<br>"
	case "medium":
		return getIconTag(mediumSeveritySource) + "<br>"
	case "low":
		return getIconTag(lowSeveritySource) + "<br>"
	}
	return ""
}

func GetBanner(banner ImageSource) string {
	return "[" + getIconTag(banner) + "](https://github.com/jfrog/frogbot#readme)"
}

func getIconTag(imageSource ImageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}

func GetSimplifiedTitle(is ImageSource) string {
	if is == NoVulnerabilityBannerSource {
		return "Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n"
	} else if is == VulnerabilitiesBannerSource {
		return "Frogbot scanned this pull request and found the issues blow: \n"
	}
	return ""
}
