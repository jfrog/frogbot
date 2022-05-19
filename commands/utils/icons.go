package utils

import (
	"fmt"
	"strings"
)

func GetSeverityTag(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
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

func GetBanner(banner ImageSource) string {
	return "[" + getIconTag(banner) + "](https://github.com/jfrog/frogbot#frogbot)"
}

func getIconTag(imageSource ImageSource) string {
	return fmt.Sprintf("![](%s)<br>", baseResourceUrl+imageSource)
}

func GetSimplifiedTitle(is ImageSource) string {
	return "Frogbot Scan:\n"
}
