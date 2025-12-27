package packagehandlers

import (
	"fmt"
	"strings"

	"github.com/beevik/etree"
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
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(pomPath); err != nil {
		return fmt.Errorf("failed to read %s: %w", pomPath, err)
	}

	root := doc.SelectElement("project")
	if root == nil {
		return fmt.Errorf("no <project> root element found in %s", pomPath)
	}

	updated := false
	updated = mpu.updateInParent(root, groupId, artifactId, fixedVersion) || updated
	updated = mpu.updateInDependencies(root, "dependencies", groupId, artifactId, fixedVersion) || updated
	updated = mpu.updateInDependencies(root, "dependencyManagement/dependencies", groupId, artifactId, fixedVersion) || updated

	if !updated {
		return fmt.Errorf("dependency %s not found in %s", toDependencyName(groupId, artifactId), pomPath)
	}

	doc.Indent(2)
	if err := doc.WriteToFile(pomPath); err != nil {
		return fmt.Errorf("failed to write %s: %w", pomPath, err)
	}

	log.Debug("Successfully updated", pomPath)
	return nil
}

func (mpu *MavenPackageUpdater) SetCommonParams(serverDetails *config.ServerDetails, depsRepo string) {
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

func (mpu *MavenPackageUpdater) updateInParent(root *etree.Element, groupId, artifactId, fixedVersion string) bool {
	parent := root.SelectElement("parent")
	if parent == nil {
		return false
	}

	gidElem := parent.SelectElement("groupId")
	aidElem := parent.SelectElement("artifactId")
	verElem := parent.SelectElement("version")

	if gidElem != nil && aidElem != nil && verElem != nil &&
		gidElem.Text() == groupId && aidElem.Text() == artifactId {
		verElem.SetText(fixedVersion)
		log.Debug("Updated parent", toDependencyName(groupId, artifactId), "to", fixedVersion)
		return true
	}
	return false
}

func (mpu *MavenPackageUpdater) updateInDependencies(root *etree.Element, path, groupId, artifactId, fixedVersion string) bool {
	depsContainer := root.FindElement(path)
	if depsContainer == nil {
		return false
	}

	for _, dep := range depsContainer.SelectElements("dependency") {
		gidElem := dep.SelectElement("groupId")
		aidElem := dep.SelectElement("artifactId")
		verElem := dep.SelectElement("version")

		if gidElem != nil && aidElem != nil && verElem != nil &&
			gidElem.Text() == groupId && aidElem.Text() == artifactId {

			version := verElem.Text()
			if propertyName, isProperty := extractPropertyName(version); isProperty {
				if mpu.updateProperty(root, propertyName, fixedVersion) {
					log.Debug("Updated property", propertyName, "to", fixedVersion)
					return true
				}
			}

			verElem.SetText(fixedVersion)
			log.Debug("Updated dependency", toDependencyName(groupId, artifactId), "to", fixedVersion)
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

func (mpu *MavenPackageUpdater) updateProperty(root *etree.Element, propertyName, newValue string) bool {
	props := root.SelectElement("properties")
	if props == nil {
		return false
	}

	propElem := props.SelectElement(propertyName)
	if propElem != nil {
		propElem.SetText(newValue)
		return true
	}
	return false
}
