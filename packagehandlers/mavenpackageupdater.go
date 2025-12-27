package packagehandlers

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
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
	Properties           mavenProperties     `xml:"properties"`
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

	groupId, artifactId, err := parseMavenCoordinate(vulnDetails.ImpactedDependencyName)
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

	updated := mpu.updateInParent(&project, groupId, artifactId, fixedVersion)
	if !updated {
		updated = mpu.updateInDependencies(project.Dependencies, groupId, artifactId, fixedVersion, &project)
	}
	if !updated && project.DependencyManagement != nil {
		updated = mpu.updateInDependencies(project.DependencyManagement.Dependencies, groupId, artifactId, fixedVersion, &project)
	}

	if !updated {
		return fmt.Errorf("dependency %s not found in %s", toMavenCoordinate(groupId, artifactId), pomPath)
	}
	return mpu.writePom(pomPath, &project)
}

func (mpu *MavenPackageUpdater) SetCommonParams(serverDetails *config.ServerDetails, depsRepo string) {}

func parseMavenCoordinate(coordinate string) (groupId, artifactId string, err error) {
	parts := strings.Split(coordinate, mavenCoordinateSeparator)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid Maven coordinate: %s. Expected format 'groupId:artifactId'", coordinate)
	}
	return parts[0], parts[1], nil
}

func toMavenCoordinate(groupId, artifactId string) string {
	return groupId + mavenCoordinateSeparator + artifactId
}

func (mpu *MavenPackageUpdater) updateInParent(project *mavenProject, groupId, artifactId, fixedVersion string) bool {
	if project.Parent != nil && project.Parent.GroupId == groupId && project.Parent.ArtifactId == artifactId {
		project.Parent.Version = fixedVersion
		log.Debug("Updated parent", toMavenCoordinate(groupId, artifactId), "to", fixedVersion)
		return true
	}
	return false
}

func (mpu *MavenPackageUpdater) updateInDependencies(deps []mavenDep, groupId, artifactId, fixedVersion string, project *mavenProject) bool {
	for i, dep := range deps {
		if dep.GroupId == groupId && dep.ArtifactId == artifactId {
			if propertyName, isProperty := extractPropertyName(dep.Version); isProperty {
				if mpu.updateProperty(project, propertyName, fixedVersion) {
					log.Debug("Updated property", propertyName, "to", fixedVersion)
					return true
				}
			}
			deps[i].Version = fixedVersion
			log.Debug("Updated dependency", toMavenCoordinate(groupId, artifactId), "to", fixedVersion)
			return true
		}
	}
	return false
}

func extractPropertyName(version string) (string, bool) {
	if strings.HasPrefix(version, propertyPrefix) && strings.HasSuffix(version, propertySuffix) {
		return strings.TrimSuffix(strings.TrimPrefix(version, propertyPrefix), propertySuffix), true
	}
	return "", false
}

func (mpu *MavenPackageUpdater) updateProperty(project *mavenProject, propertyName, newValue string) bool {
	for i, prop := range project.Properties.Props {
		if prop.XMLName.Local == propertyName {
			project.Properties.Props[i].Value = newValue
			return true
		}
	}
	return false
}

func (mpu *MavenPackageUpdater) writePom(pomPath string, project *mavenProject) error {
	output, err := xml.MarshalIndent(project, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %w", err)
	}

	if err := os.WriteFile(pomPath, []byte(xml.Header+string(output)), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", pomPath, err)
	}

	log.Debug("Successfully updated", pomPath)
	return nil
}
