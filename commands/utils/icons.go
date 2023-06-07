package utils

import (
	"fmt"
	"strings"
)

func GetSeverityTag(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetIconTag(criticalSeveritySource) + "<br>"
	case "high":
		return GetIconTag(highSeveritySource) + "<br>"
	case "medium":
		return GetIconTag(mediumSeveritySource) + "<br>"
	case "low":
		return GetIconTag(lowSeveritySource) + "<br>"
	}
	return ""
}

func GetBanner(banner ImageSource) string {
	return "[" + GetIconTag(banner) + "](https://github.com/jfrog/frogbot#readme)"
}

func GetIconTag(imageSource ImageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}

func GetSimplifiedTitle(is ImageSource) string {
	if is == NoVulnerabilityBannerSource {
		return "** 👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies. ** \n"
	} else if is == VulnerabilitiesBannerSource {
		return "** 🚨 Frogbot scanned this pull request and found the below: **\n"
	}
	return ""
}
