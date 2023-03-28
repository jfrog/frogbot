package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type goFixVersionsMapping struct {
	standard StandardFixVersionsMapping
}

func (g goFixVersionsMapping) AddToMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*FixVersionInfo) error {
	// Trim 'v' prefix in case of Go package
	vulnerability.ImpactedDependencyVersion = strings.TrimPrefix(vulnerability.ImpactedDependencyVersion, "v")
	return g.standard.AddToMap(vulnerability, fixVersionsMap)
}
