package main

import (
	"fmt"
	"strings"
)

type imageSource string

const (
	baseResourceUrl                         = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"
	noVulnerabilityBannerSource imageSource = "noVulnerabilityBanner.png"
	vulnerabilitiesBannerSource imageSource = "vulnerabilitiesBanner.png"
	criticalSeveritySource      imageSource = "criticalSeverity.png"
	highSeveritySource          imageSource = "highSeverity.png"
	mediumSeveritySource        imageSource = "mediumSeverity.png"
	lowSeveritySource           imageSource = "lowSeverity.png"
)

func GetIconTag(imageSource imageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}

func GetIconSource(iconName string) (imageSource imageSource) {
	switch strings.ToLower(iconName) {
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
