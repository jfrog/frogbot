package utils

import (
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"strings"
)

type StandardFixVersionsMapping struct {
	tech            coreutils.Technology
	workDirs        []string
	mavenVersionMap map[string][]string
}

func (s StandardFixVersionsMapping) AddToMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*FixVersionInfo) error {
	// todo this is only maven

	fixVulnerability, err := s.shouldFixVulnerability(vulnerability)
	if err != nil {
		return err
	}
	if !fixVulnerability {
		return nil
	}
	vulnFixVersion, err := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if err != nil || vulnFixVersion == "" {
		return nil
	}

	if fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above impacted package, we select the maximum fix version.
		fixVersionInfo.UpdateFixVersion(vulnFixVersion)
	} else {
		// First appearance of a version that fixes the current impacted package
		fixVersionsMap[vulnerability.ImpactedDependencyName] = NewFixVersionInfo(vulnFixVersion, vulnerability.Technology)
	}
	return nil
}

// getMinimalFixVersion that fixes the current impactedPackage
// FixVersions array is sorted
// MinimalFixVersion is the smallest version change possible with priority on upgrading version
func getMinimalFixVersion(impactedPackageVersion string, fixVersions []string) (minimalVersion string, err error) {
	if len(fixVersions) == 0 {
		return
	}
	// Todo move this to it's own
	// Trim 'v' prefix in case of Go package
	currVersionStr := strings.TrimPrefix(impactedPackageVersion, "v")
	currVersion := version.NewVersion(currVersionStr)
	currVersionMajor, err := currVersion.GetMajor()
	if err != nil {
		return
	}
	// Upgrade
	for _, fixVersion := range fixVersions {
		fixVersionCandidate := parseVersionChangeString(fixVersion)
		suggestVersion := version.NewVersion(fixVersion)
		suggestedMajorVersion, err := suggestVersion.GetMajor()
		isMajorUpgrade := currVersionMajor != suggestedMajorVersion
		if currVersion.Compare(fixVersionCandidate) > 0 && !isMajorUpgrade {
			return fixVersionCandidate, err
		}
	}
	// Downgrade
	for i := len(fixVersions) - 1; i >= 0; i-- {
		fixVersionCandidate := parseVersionChangeString(fixVersions[i])
		suggestVersion := version.NewVersion(fixVersions[i])
		suggestedMajorVersion, err := suggestVersion.GetMajor()
		isMajorUpgrade := currVersionMajor != suggestedMajorVersion
		if currVersion.Compare(fixVersionCandidate) < 0 && !isMajorUpgrade {
			return fixVersionCandidate, err
		}
	}
	// No suggestions found
	return
}

func GetCompatibleFixVersionsMap(technology coreutils.Technology, workDirs []string, mavenDepMap map[string][]string) *StandardFixVersionsMapping {
	switch technology {
	case coreutils.Maven:
		{
			return &StandardFixVersionsMapping{tech: technology, workDirs: workDirs, mavenVersionMap: mavenDepMap}
		}
	default:
		return &StandardFixVersionsMapping{tech: technology, workDirs: workDirs, mavenVersionMap: mavenDepMap}
	}
}

func (s StandardFixVersionsMapping) shouldFixVulnerability(vulnerability *formats.VulnerabilityOrViolationRow) (bool, error) {
	if vulnerability.Technology == coreutils.Maven {
		return s.shouldFixMavenVulnerability(vulnerability)
	}
	return true, nil
}

func (s StandardFixVersionsMapping) shouldFixMavenVulnerability(vulnerability *formats.VulnerabilityOrViolationRow) (bool, error) {
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
