package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
)

type mavenFixVersionsMapping struct {
	workDirs        []string
	mavenVersionMap map[string][]string
	standard        StandardFixVersionsMapping
}

func (s mavenFixVersionsMapping) AddToMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*FixVersionInfo) error {
	fixVulnerability, err := s.shouldFixMavenVulnerability(vulnerability)
	if err != nil {
		return err
	}
	if !fixVulnerability {
		return nil
	}
	return s.standard.AddToMap(vulnerability, fixVersionsMap)
}

func (s mavenFixVersionsMapping) shouldFixMavenVulnerability(vulnerability *formats.VulnerabilityOrViolationRow) (bool, error) {
	// In Maven, fix only direct dependencies
	if len(s.mavenVersionMap) == 0 {
		// Get all Maven dependencies and plugins from pom.xml
		s.mavenVersionMap = make(map[string][]string)
		for _, workingDir := range s.workDirs {
			if workingDir == RootDir {
				workingDir = ""
			}
			if err := GetVersionProperties(workingDir, s.mavenVersionMap); err != nil {
				return false, err
			}
		}
	}
	if _, exist := s.mavenVersionMap[vulnerability.ImpactedDependencyName]; !exist {
		return false, nil
	}
	return true, nil
}
