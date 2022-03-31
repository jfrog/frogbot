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

func GetBanner(banner imageSource) string {
	return "[" + getIconTag(banner) + "](https://github.com/jfrog/frogbot#frogbot)"
}

func getIconTag(imageSource imageSource) string {
	return fmt.Sprintf("![](%s)", baseResourceUrl+imageSource)
}
