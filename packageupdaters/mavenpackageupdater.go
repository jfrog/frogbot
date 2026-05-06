package packageupdaters

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v2/utils"
)

const (
	mavenDependencySeparator = ":"
	propertyPrefix           = "${"
	propertySuffix           = "}"
	pomFileName              = "pom.xml"
)

type MavenPackageUpdater struct{}

type mavenProject struct {
	XMLName              xml.Name            `xml:"project"`
	Parent               *mavenDep           `xml:"parent"`
	Properties           *mavenProperties    `xml:"properties"`
	Dependencies         []mavenDep          `xml:"dependencies>dependency"`
	DependencyManagement *mavenDepManagement `xml:"dependencyManagement"`
}

type mavenProperties struct {
	Props []mavenProperty `xml:",any"`
}

type mavenProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type mavenDep struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type mavenDepManagement struct {
	Dependencies []mavenDep `xml:"dependencies>dependency"`
}

func (m *MavenPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if !vulnDetails.IsDirectDependency {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}

	groupId, artifactId, err := parseDependencyName(vulnDetails.ImpactedDependencyName)
	if err != nil {
		return err
	}

	pomPaths := GetVulnerabilityLocations(vulnDetails, []string{pomFileName}, []string{})
	if len(pomPaths) == 0 {
		return fmt.Errorf("no pom.xml locations found for %s - Components array is empty or missing Location data", vulnDetails.ImpactedDependencyName)
	}
	log.Verbose(fmt.Sprintf("Found vulnerability %s occurrences for component %s in %s", vulnDetails.IssueId, vulnDetails.ImpactedDependencyVersion, strings.Join(pomPaths, ", ")))

	var failingDescriptors []string
	for _, pomPath := range pomPaths {
		if fixErr := m.updatePomFile(pomPath, groupId, artifactId, vulnDetails.SuggestedFixedVersion); fixErr != nil {
			log.Warn(fixErr.Error())
			failedFixErrorMsg := fmt.Errorf("failed to fix '%s' in descriptor '%s': %w", vulnDetails.ImpactedDependencyName, pomPath, fixErr)
			err = errors.Join(err, failedFixErrorMsg)
			failingDescriptors = append(failingDescriptors, pomPath)
		}
		log.Debug("Updated successfully " + pomPath)
	}

	if err != nil {
		return fmt.Errorf("encountered errors while fixing '%s' vulnerability in descriptors [%s]: %w", vulnDetails.ImpactedDependencyName, strings.Join(failingDescriptors, ", "), err)
	}
	return nil
}

func (m *MavenPackageUpdater) updatePomFile(pomPath, groupId, artifactId, fixedVersion string) error {
	//#nosec G304 -- pomPath from descriptor discovery in the scanned repository.
	content, err := os.ReadFile(pomPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", pomPath, err)
	}

	var project mavenProject
	if err = xml.Unmarshal(content, &project); err != nil {
		return fmt.Errorf("failed to parse %s: %w", pomPath, err)
	}

	// Working buffer for the update chain. Each update returns a new slice (e.g. regexp.ReplaceAll),
	// so we never mutate the original content. No backup or revert—we only write to the file on success.
	currentContent := content
	var updatedAny bool

	if updated, c := m.updateInParent(&project, groupId, artifactId, fixedVersion, currentContent); updated {
		currentContent = c
		updatedAny = true
	}
	if updated, c := m.updateInDependencies(&project, project.Dependencies, groupId, artifactId, fixedVersion, currentContent); updated {
		currentContent = c
		updatedAny = true
	}
	if project.DependencyManagement != nil {
		if updated, c := m.updateInDependencies(&project, project.DependencyManagement.Dependencies, groupId, artifactId, fixedVersion, currentContent); updated {
			currentContent = c
			updatedAny = true
		}
	}

	if !updatedAny {
		return fmt.Errorf("dependency %s not found in %s", toDependencyName(groupId, artifactId), pomPath)
	}

	//#nosec G703 G306 -- path from scan workflow; 0644 for VCS-tracked sources.
	if err = os.WriteFile(pomPath, currentContent, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", pomPath, err)
	}
	return nil
}

func parseDependencyName(dependencyName string) (groupId, artifactId string, err error) {
	parts := strings.Split(dependencyName, mavenDependencySeparator)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid Maven dependency name: %s. Expected format 'groupId:artifactId'", dependencyName)
	}
	return parts[0], parts[1], nil
}

func toDependencyName(groupId, artifactId string) string {
	return groupId + mavenDependencySeparator + artifactId
}

func (m *MavenPackageUpdater) updateInParent(project *mavenProject, groupId, artifactId, fixedVersion string, content []byte) (bool, []byte) {
	if project.Parent == nil {
		return false, content
	}

	if project.Parent.GroupId == groupId && project.Parent.ArtifactId == artifactId {
		pattern := regexp.MustCompile(`(?s)(<parent>\s*<groupId>` + regexp.QuoteMeta(groupId) + `</groupId>\s*<artifactId>` + regexp.QuoteMeta(artifactId) + `</artifactId>\s*<version>)[^<]+(</version>)`)
		newContent := pattern.ReplaceAll(content, []byte("${1}"+fixedVersion+"${2}"))
		if !bytes.Equal(content, newContent) {
			log.Debug("Updated parent", toDependencyName(groupId, artifactId), "to", fixedVersion)
			return true, newContent
		}
	}
	return false, content
}

func (m *MavenPackageUpdater) updateInDependencies(project *mavenProject, deps []mavenDep, groupId, artifactId, fixedVersion string, content []byte) (bool, []byte) {
	for _, dep := range deps {
		if dep.GroupId == groupId && dep.ArtifactId == artifactId {
			if propertyName, isProperty := extractPropertyName(dep.Version); isProperty {
				return m.updateProperty(project, propertyName, fixedVersion, content)
			}

			pattern := regexp.MustCompile(`(?s)(<groupId>` + regexp.QuoteMeta(groupId) + `</groupId>\s*<artifactId>` + regexp.QuoteMeta(artifactId) + `</artifactId>\s*<version>)[^<]+(</version>)`)
			newContent := pattern.ReplaceAll(content, []byte("${1}"+fixedVersion+"${2}"))
			if !bytes.Equal(content, newContent) {
				log.Debug("Updated dependency", toDependencyName(groupId, artifactId), "to", fixedVersion)
				return true, newContent
			}
		}
	}
	return false, content
}

func extractPropertyName(version string) (string, bool) {
	if strings.HasPrefix(version, propertyPrefix) && strings.HasSuffix(version, propertySuffix) {
		return strings.TrimSuffix(strings.TrimPrefix(version, propertyPrefix), propertySuffix), true
	}
	return "", false
}

func (m *MavenPackageUpdater) updateProperty(project *mavenProject, propertyName, newValue string, content []byte) (bool, []byte) {
	if project.Properties == nil {
		return false, content
	}

	for _, prop := range project.Properties.Props {
		if prop.XMLName.Local == propertyName {
			pattern := regexp.MustCompile(`(<` + regexp.QuoteMeta(propertyName) + `>)[^<]+(</` + regexp.QuoteMeta(propertyName) + `>)`)
			newContent := pattern.ReplaceAll(content, []byte("${1}"+newValue+"${2}"))
			if !bytes.Equal(content, newContent) {
				return true, newContent
			}
		}
	}
	return false, content
}
