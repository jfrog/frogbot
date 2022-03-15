package main

import "fmt"

const (
	baseSourceUrl               = "https://raw.githubusercontent.com/jfrog/frobot/master/resources/"
	noVulnerabilityBannerSource = "noVulnerabilityBanner.png"
	vulnerabilitiesBannerSource = "vulnerabilitiesBanner.png"
	criticalSeveritySource      = "criticalSeverity.png"
	highSeveritySource          = "highSeverity.png"
	mediumSeveritySource        = "mediumSeverity.png"
	lowSeveritySource           = "lowSeverity.png"
)

func GetIconTag(iconSource string) string {
	return fmt.Sprintf("![](%s)", baseSourceUrl+iconSource)
}

func GetIconSource(iconName string) (iconSource string) {
	switch iconName {

	case "critical":
		return criticalSeveritySource

	case "high":
		return highSeveritySource

	case "medium":
		return mediumSeveritySource

	case "low":
		return lowSeveritySource
	}
	return
}
