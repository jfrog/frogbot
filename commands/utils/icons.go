package utils

import (
	"fmt"
	"strings"
)

func getSeverityTag(iconName IconName, applicability string) string {
	if applicability == "Not Applicable" {
		return getNotApplicableIconTags(iconName)
	}
	return getApplicableIconTags(iconName)
}

func getNotApplicableIconTags(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetIconTag(notApplicableCriticalSeveritySource) + "<br>"
	case "high":
		return GetIconTag(notApplicableHighSeveritySource) + "<br>"
	case "medium":
		return GetIconTag(notApplicableMediumSeveritySource) + "<br>"
	case "low":
		return GetIconTag(notApplicableLowSeveritySource) + "<br>"
	}
	return GetIconTag(notApplicableUnknownSeveritySource) + "<br>"
}

func getApplicableIconTags(iconName IconName) string {
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
	return GetIconTag(unknownSeveritySource) + "<br>"
}

func GetBanner(banner ImageSource) string {
	return "[" + GetIconTag(banner) + "](https://github.com/jfrog/frogbot#readme)"
}

func GetIconTag(imageSource ImageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}

func GetSimplifiedTitle(is ImageSource) string {
	switch is {
	case NoVulnerabilityPrBannerSource:
		return "**👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies.** \n"
	case VulnerabilitiesPrBannerSource:
		return "**🚨 Frogbot scanned this pull request and found the below:**\n"
	case VulnerabilitiesFixPrBannerSource:
		return "**🚨 This automated pull request was created by Frogbot and fixes the below:**\n"
	default:
		return ""
	}
}
