package utils

import (
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
)

type GenericFixVersionsMap struct {
}

func (s GenericFixVersionsMap) AddToMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*FixVersionInfo) error {
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

// getMinimalFixVersion finds the smallest version change possible to fix the current impactedPackage version.
// The fixVersions array returns sorted from Xray.
// The priority order is as follows:
// Patch upgrade ,Minor upgrade ,Patch downgrade , Minor downgrade.
// Currently major version changes are not supported.
func getMinimalFixVersion(impactedPackageVersion string, fixVersions []string) (minimalVersion string, err error) {
	if len(fixVersions) == 0 {
		return
	}
	currVersion := version.NewVersion(impactedPackageVersion)
	currVersionMajor, err := currVersion.GetMajor()
	if err != nil {
		return
	}
	// Search possible upgrade
	for _, fixVersion := range fixVersions {
		fixVersionCandidate, err, isMajorUpgrade := parseVersionCandidate(fixVersion, currVersionMajor)
		if currVersion.Compare(fixVersionCandidate) > 0 && !isMajorUpgrade {
			return fixVersionCandidate, err
		}
	}
	// Search possible downgrade, reverse search in sorted array
	for i := len(fixVersions) - 1; i >= 0; i-- {
		fixVersionCandidate, err, isMajorUpgrade := parseVersionCandidate(fixVersions[i], currVersionMajor)
		if currVersion.Compare(fixVersionCandidate) < 0 && !isMajorUpgrade {
			return fixVersionCandidate, err
		}
	}
	// No suggestions found
	return
}

func parseVersionCandidate(fixVersion string, currVersionMajor string) (string, error, bool) {
	fixVersionCandidate := parseVersionChangeString(fixVersion)
	suggestVersion := version.NewVersion(fixVersion)
	suggestedMajorVersion, err := suggestVersion.GetMajor()
	isMajorUpgrade := currVersionMajor != suggestedMajorVersion
	return fixVersionCandidate, err, isMajorUpgrade
}

func GetCompatibleFixVersionsMap(technology coreutils.Technology, workDirs []string, mavenDepMap map[string][]string) FixVersionSuggestions {
	switch technology {
	case coreutils.Maven:
		{
			return mavenFixVersionsMap{workDirs: workDirs, mavenVersionMap: mavenDepMap, standard: GenericFixVersionsMap{}}
		}
	case coreutils.Go:
		{
			return goFixVersionsMap{standard: GenericFixVersionsMap{}}
		}
	default:
		return GenericFixVersionsMap{}
	}
}
