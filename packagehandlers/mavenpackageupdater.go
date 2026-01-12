package packagehandlers

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	mavenCoordinateSeparator = ":"
	propertyPrefix           = "${"
	propertySuffix           = "}"
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

func (mpu *MavenPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
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

	pomPaths := mpu.getPomPaths(vulnDetails)
	if len(pomPaths) == 0 {
		return fmt.Errorf("no pom.xml locations found for %s - Components array is empty or missing Location data", vulnDetails.ImpactedDependencyName)
	}

	var errors []string
	for _, pomPath := range pomPaths {
		if err := mpu.updatePomFile(pomPath, groupId, artifactId, vulnDetails.SuggestedFixedVersion); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", pomPath, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to update pom.xml files:\n%s", strings.Join(errors, "\n"))
	}
	return nil
}

func (mpu *MavenPackageUpdater) getPomPaths(vulnDetails *utils.VulnerabilityDetails) []string {
	var pomPaths []string
	for _, component := range vulnDetails.Components {
		if component.Location != nil && component.Location.File != "" {
			pomPaths = append(pomPaths, component.Location.File)
		}
	}
	return pomPaths
}

func (mpu *MavenPackageUpdater) updatePomFile(pomPath, groupId, artifactId, fixedVersion string) error {
	content, err := os.ReadFile(pomPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", pomPath, err)
	}

	var project mavenProject
	if err := xml.Unmarshal(content, &project); err != nil {
		return fmt.Errorf("failed to parse %s: %w", pomPath, err)
	}

	updated := false
	newContent := content

	if updated, newContent = mpu.updateInParent(&project, groupId, artifactId, fixedVersion, newContent); updated {
		if err := os.WriteFile(pomPath, newContent, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", pomPath, err)
		}
		log.Debug("Successfully updated", pomPath)
		return nil
	}

	if updated, newContent = mpu.updateInDependencies(&project, project.Dependencies, groupId, artifactId, fixedVersion, newContent); updated {
		if err := os.WriteFile(pomPath, newContent, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", pomPath, err)
		}
		log.Debug("Successfully updated", pomPath)
		return nil
	}

	if project.DependencyManagement != nil {
		if updated, newContent = mpu.updateInDependencies(&project, project.DependencyManagement.Dependencies, groupId, artifactId, fixedVersion, newContent); updated {
			if err := os.WriteFile(pomPath, newContent, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", pomPath, err)
			}
			log.Debug("Successfully updated", pomPath)
			return nil
		}
	}

	return fmt.Errorf("dependency %s not found in %s", toDependencyName(groupId, artifactId), pomPath)
}

func parseDependencyName(dependencyName string) (groupId, artifactId string, err error) {
	parts := strings.Split(dependencyName, mavenCoordinateSeparator)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid Maven dependency name: %s. Expected format 'groupId:artifactId'", dependencyName)
	}
	return parts[0], parts[1], nil
}

func toDependencyName(groupId, artifactId string) string {
	return groupId + mavenCoordinateSeparator + artifactId
}

func (mpu *MavenPackageUpdater) updateInParent(project *mavenProject, groupId, artifactId, fixedVersion string, content []byte) (bool, []byte) {
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

func (mpu *MavenPackageUpdater) updateInDependencies(project *mavenProject, deps []mavenDep, groupId, artifactId, fixedVersion string, content []byte) (bool, []byte) {
	for _, dep := range deps {
		if dep.GroupId == groupId && dep.ArtifactId == artifactId {
			if propertyName, isProperty := extractPropertyName(dep.Version); isProperty {
				return mpu.updateProperty(project, propertyName, fixedVersion, content)
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

func (mpu *MavenPackageUpdater) updateProperty(project *mavenProject, propertyName, newValue string, content []byte) (bool, []byte) {
	if project.Properties == nil {
		return false, content
	}

	for _, prop := range project.Properties.Props {
		if prop.XMLName.Local == propertyName {
			pattern := regexp.MustCompile(`(<` + regexp.QuoteMeta(propertyName) + `>)[^<]+(</` + regexp.QuoteMeta(propertyName) + `>)`)
			newContent := pattern.ReplaceAll(content, []byte("${1}"+newValue+"${2}"))
			if !bytes.Equal(content, newContent) {
				log.Debug("Updated property", propertyName, "to", newValue)
				return true, newContent
			}
		}
	}
	return false, content
}
