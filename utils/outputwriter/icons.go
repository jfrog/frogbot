package outputwriter

import (
	"fmt"
	"strings"
)

type ImageSource string
type IconName string

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	NoVulnerabilityPrBannerSource       ImageSource = "v2/noVulnerabilityBannerPR.png"
	NoVulnerabilityMrBannerSource       ImageSource = "v2/noVulnerabilityBannerMR.png"
	VulnerabilitiesPrBannerSource       ImageSource = "v2/vulnerabilitiesBannerPR.png"
	VulnerabilitiesMrBannerSource       ImageSource = "v2/vulnerabilitiesBannerMR.png"
	VulnerabilitiesFixPrBannerSource    ImageSource = "v2/vulnerabilitiesFixBannerPR.png"
	VulnerabilitiesFixMrBannerSource    ImageSource = "v2/vulnerabilitiesFixBannerMR.png"
	criticalSeveritySource              ImageSource = "v2/applicableCriticalSeverity.png"
	notApplicableCriticalSeveritySource ImageSource = "v2/notApplicableCritical.png"
	highSeveritySource                  ImageSource = "v2/applicableHighSeverity.png"
	notApplicableHighSeveritySource     ImageSource = "v2/notApplicableHigh.png"
	mediumSeveritySource                ImageSource = "v2/applicableMediumSeverity.png"
	notApplicableMediumSeveritySource   ImageSource = "v2/notApplicableMedium.png"
	lowSeveritySource                   ImageSource = "v2/applicableLowSeverity.png"
	notApplicableLowSeveritySource      ImageSource = "v2/notApplicableLow.png"
	unknownSeveritySource               ImageSource = "v2/applicableUnknownSeverity.png"
	notApplicableUnknownSeveritySource  ImageSource = "v2/notApplicableUnknown.png"

	smallCriticalSeveritySource ImageSource = "v2/smallCritical.svg"
	smallHighSeveritySource     ImageSource = "v2/smallHigh.svg"
	smallMediumSeveritySource   ImageSource = "v2/smallMedium.svg"
	smallLowSeveritySource      ImageSource = "v2/smallLow.svg"
	smallUnknownSeveritySource  ImageSource = "v2/smallUnknown.svg"
)

func getSeverityTag(iconName IconName, applicability string) string {
	if applicability == "Not Applicable" {
		return getNotApplicableIconTags(iconName)
	}
	return getApplicableIconTags(iconName)
}

func getSmallSeverityTag(iconName IconName) string {
	return getSmallApplicableIconTags(iconName)
}

func getNotApplicableIconTags(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetIconTag(notApplicableCriticalSeveritySource, "critical (not applicable)") + "<br>"
	case "high":
		return GetIconTag(notApplicableHighSeveritySource, "high (not applicable)") + "<br>"
	case "medium":
		return GetIconTag(notApplicableMediumSeveritySource, "medium (not applicable)") + "<br>"
	case "low":
		return GetIconTag(notApplicableLowSeveritySource, "low (not applicable)") + "<br>"
	}
	return GetIconTag(notApplicableUnknownSeveritySource, "unknown (not applicable)") + "<br>"
}

func getApplicableIconTags(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetIconTag(criticalSeveritySource, "critical") + "<br>"
	case "high":
		return GetIconTag(highSeveritySource, "high") + "<br>"
	case "medium":
		return GetIconTag(mediumSeveritySource, "medium") + "<br>"
	case "low":
		return GetIconTag(lowSeveritySource, "low") + "<br>"
	}
	return GetIconTag(unknownSeveritySource, "unknown") + "<br>"
}

func getSmallApplicableIconTags(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetImgTag(smallCriticalSeveritySource, "")
	case "high":
		return GetImgTag(smallHighSeveritySource, "")
	case "medium":
		return GetImgTag(smallMediumSeveritySource, "")
	case "low":
		return GetImgTag(smallLowSeveritySource, "")
	}
	return GetImgTag(smallUnknownSeveritySource, "")
}

func GetBanner(banner ImageSource) string {
	return GetMarkdownCenterTag(MarkAsLink(GetIconTag(banner, GetSimplifiedTitle(banner)), FrogbotDocumentationUrl))
}

func GetIconTag(imageSource ImageSource, alt string) string {
	return fmt.Sprintf("!%s", MarkAsLink(alt, fmt.Sprintf("%s%s", baseResourceUrl, imageSource)))
}

func GetImgTag(imageSource ImageSource, alt string) string {
	return fmt.Sprintf("<img src=\"%s%s\" alt=\"%s\"/>", baseResourceUrl, imageSource, alt)
}

func GetSimplifiedTitle(is ImageSource) string {
	switch is {
	case NoVulnerabilityPrBannerSource:
		return "👍 Frogbot scanned this pull request and did not find any new security issues."
	case VulnerabilitiesPrBannerSource:
		return "🚨 Frogbot scanned this pull request and found the below:"
	case VulnerabilitiesFixPrBannerSource:
		return "🚨 This automated pull request was created by Frogbot and fixes the below:"
	case NoVulnerabilityMrBannerSource:
		return "👍 Frogbot scanned this merge request and did not find any new security issues."
	case VulnerabilitiesMrBannerSource:
		return "🚨 Frogbot scanned this merge request and found the below:"
	case VulnerabilitiesFixMrBannerSource:
		return "🚨 This automated merge request was created by Frogbot and fixes the below:"
	default:
		return ""
	}
}
