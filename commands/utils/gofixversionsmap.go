package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type goFixVersionsMap struct {
	standard GenericFixVersionsMap
}

func (g *goFixVersionsMap) AddToMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*FixVersionInfo) error {
	trimVersionPrefix(vulnerability)
	return g.standard.AddToMap(vulnerability, fixVersionsMap)
}

func trimVersionPrefix(vulnerability *formats.VulnerabilityOrViolationRow) {
	// Trim 'v' prefix in case of Go package
	vulnerability.ImpactedDependencyVersion = strings.TrimPrefix(vulnerability.ImpactedDependencyVersion, "v")
}
