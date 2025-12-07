package packagehandlers

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies/java"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"
	"os"
	"path/filepath"
	"strings"
)

const MavenVersionNotAvailableErrorFormat = "Version %s is not available for artifact"

type gavCoordinate struct {
	GroupId                     string `xml:"groupId"`
	ArtifactId                  string `xml:"artifactId"`
	Version                     string `xml:"version"`
	foundInDependencyManagement bool
}

func (gc *gavCoordinate) isEmpty() bool {
	return gc.GroupId == "" && gc.ArtifactId == "" && gc.Version == ""
}

func (gc *gavCoordinate) trimSpaces() *gavCoordinate {
	gc.GroupId = strings.TrimSpace(gc.GroupId)
	gc.ArtifactId = strings.TrimSpace(gc.ArtifactId)
	gc.Version = strings.TrimSpace(gc.Version)
	return gc
}

type mavenDependency struct {
	gavCoordinate
	Dependencies         []mavenDependency `xml:"dependencies>dependency"`
	DependencyManagement []mavenDependency `xml:"dependencyManagement>dependencies>dependency"`
	Plugins              []mavenPlugin     `xml:"build>plugins>plugin"`
}

func (md *mavenDependency) collectMavenDependencies(foundInDependencyManagement bool) []gavCoordinate {
	var result []gavCoordinate
	if !md.isEmpty() {
		md.foundInDependencyManagement = foundInDependencyManagement
		result = append(result, *md.trimSpaces())
	}
	for _, dependency := range md.Dependencies {
		result = append(result, dependency.collectMavenDependencies(foundInDependencyManagement)...)
	}
	for _, dependency := range md.DependencyManagement {
		result = append(result, dependency.collectMavenDependencies(true)...)
	}
	for _, plugin := range md.Plugins {
		result = append(result, plugin.collectMavenPlugins()...)
	}

	return result
}

type mavenPlugin struct {
	gavCoordinate
	NestedPlugins []mavenPlugin `xml:"configuration>plugins>plugin"`
}

func (mp *mavenPlugin) collectMavenPlugins() []gavCoordinate {
	var result []gavCoordinate
	if !mp.isEmpty() {
		result = append(result, *mp.trimSpaces())
	}
	for _, plugin := range mp.NestedPlugins {
		result = append(result, plugin.collectMavenPlugins()...)
	}
	return result
}

// fillDependenciesMap collects direct dependencies from the pomPath pom.xml file.
// If the version of a dependency is set in another property section, it is added as its value in the map.
func (mph *MavenPackageHandler) fillDependenciesMap(pomPath string) error {
	contentBytes, err := os.ReadFile(filepath.Clean(pomPath))
	if err != nil {
		return errors.New("couldn't read pom.xml file: " + err.Error())
	}
	mavenDependencies, err := getMavenDependencies(contentBytes)
	if err != nil {
		return err
	}
	for _, dependency := range mavenDependencies {
		if dependency.Version == "" {
			continue
		}
		depName := fmt.Sprintf("%s:%s", dependency.GroupId, dependency.ArtifactId)
		if _, exist := mph.pomDependencies[depName]; !exist {
			mph.pomDependencies[depName] = pomDependencyDetails{foundInDependencyManagement: dependency.foundInDependencyManagement, currentVersion: dependency.Version}
		}
		if strings.HasPrefix(dependency.Version, "${") {
			trimmedVersion := strings.Trim(dependency.Version, "${}")
			if !slices.Contains(mph.pomDependencies[depName].properties, trimmedVersion) {
				mph.pomDependencies[depName] = pomDependencyDetails{
					properties:                  append(mph.pomDependencies[depName].properties, trimmedVersion),
					currentVersion:              dependency.Version,
					foundInDependencyManagement: dependency.foundInDependencyManagement,
				}
			}
		}
	}
	return nil
}

// Extract all dependencies from the input pom.xml
// pomXmlContent - The pom.xml content
func getMavenDependencies(pomXmlContent []byte) (result []gavCoordinate, err error) {
	var dependencies mavenDependency
	if err = xml.Unmarshal(pomXmlContent, &dependencies); err != nil {
		err = fmt.Errorf("failed to unmarshal the current pom.xml:\n%s, error received:\n%w"+string(pomXmlContent), err)
		return
	}
	result = append(result, dependencies.collectMavenDependencies(false)...)
	return
}

type pomPath struct {
	PomPath string `json:"pomPath"`
}

type pomDependencyDetails struct {
	properties                  []string
	currentVersion              string
	foundInDependencyManagement bool
}

func NewMavenPackageHandler(scanDetails *utils.ScanDetails) *MavenPackageHandler {
	depTreeParams := &java.DepTreeParams{
		Server:                  scanDetails.ServerDetails,
		DepsRepo:                scanDetails.DepsRepo,
		IsMavenDepTreeInstalled: true,
	}
	// The mvn-dep-tree plugin has already been installed during the audit dependency tree build phase,
	// Therefore, we set the `isDepTreeInstalled` flag to true
	mavenDepTreeManager := java.NewMavenDepTreeManager(depTreeParams, java.Projects)
	return &MavenPackageHandler{MavenDepTreeManager: mavenDepTreeManager}
}

type MavenPackageHandler struct {
	CommonPackageHandler
	// pomDependencies holds a map of direct dependencies found in pom.xml.
	pomDependencies map[string]pomDependencyDetails
	// pomPaths holds the paths to all the pom.xml files that are related to the current project.
	pomPaths []pomPath
	// mavenDepTreeManager handles the installation and execution of the maven-dep-tree to obtain all the project poms and running mvn commands
	*java.MavenDepTreeManager
}

func (mph *MavenPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	// When resolution from an Artifactory server is necessary, a settings.xml file will be generated, and its path will be set in mph.
	if mph.GetDepsRepo() != "" {
		var clearMavenDepTreeRun func() error
		_, clearMavenDepTreeRun, err = mph.CreateTempDirWithSettingsXmlIfNeeded()
		if err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, clearMavenDepTreeRun())
		}()
	}

	err = mph.getProjectPoms()
	if err != nil {
		return err
	}

	// Get direct dependencies for each pom.xml file
	if mph.pomDependencies == nil {
		mph.pomDependencies = make(map[string]pomDependencyDetails)
	}
	for _, pp := range mph.pomPaths {
		if err = mph.fillDependenciesMap(pp.PomPath); err != nil {
			return err
		}
	}

	var depDetails pomDependencyDetails
	var exists bool
	// Check if the impacted package is a direct dependency
	impactedDependency := vulnDetails.ImpactedDependencyName
	if depDetails, exists = mph.pomDependencies[impactedDependency]; !exists {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
	if len(depDetails.properties) > 0 {
		return mph.updateProperties(&depDetails, vulnDetails.SuggestedFixedVersion)
	}

	return mph.updatePackageVersion(vulnDetails.ImpactedDependencyName, vulnDetails.SuggestedFixedVersion, depDetails.foundInDependencyManagement)
}

// Returns project's Pom paths. This function requires an execution of maven-dep-tree 'project' command prior to its execution
func (mph *MavenPackageHandler) getProjectPoms() (err error) {
	// Check if we already scanned the project pom.xml locations
	if len(mph.pomPaths) > 0 {
		return
	}

	oldSettingsXmlPath := mph.GetSettingsXmlPath()

	var depTreeOutput string
	var clearMavenDepTreeRun func() error
	if depTreeOutput, clearMavenDepTreeRun, err = mph.RunMavenDepTree(); err != nil {
		err = fmt.Errorf("failed to get project poms while running maven-dep-tree: %s", err.Error())
		if clearMavenDepTreeRun != nil {
			err = errors.Join(err, clearMavenDepTreeRun())
		}
		return
	}
	defer func() {
		err = clearMavenDepTreeRun()
		mph.SetSettingsXmlPath(oldSettingsXmlPath)
	}()

	for _, jsonContent := range strings.Split(depTreeOutput, "\n") {
		if jsonContent == "" {
			continue
		}
		// Escape backslashes in the pomPath field, to fix windows backslash parsing issues
		escapedContent := strings.ReplaceAll(jsonContent, `\`, `\\`)
		var pp pomPath
		if err = json.Unmarshal([]byte(escapedContent), &pp); err != nil {
			err = fmt.Errorf("failed to unmarshal the maven-dep-tree output. Full maven-dep-tree output:\n%s\nCurrent line:\n%s\nError details:\n%w", depTreeOutput, escapedContent, err)
			return
		}
		mph.pomPaths = append(mph.pomPaths, pp)
	}
	if len(mph.pomPaths) == 0 {
		err = errors.New("couldn't find any pom.xml files in the current project")
	}
	return
}

// Update the package version. Updates it only if the version is not a reference to a property.
func (mph *MavenPackageHandler) updatePackageVersion(impactedPackage, fixedVersion string, foundInDependencyManagement bool) error {
	updateVersionArgs := []string{
		"-U", "-B", "org.codehaus.mojo:versions-maven-plugin:use-dep-version", "-Dincludes=" + impactedPackage,
		"-DdepVersion=" + fixedVersion, "-DgenerateBackupPoms=false",
		fmt.Sprintf("-DprocessDependencies=%t", !foundInDependencyManagement),
		fmt.Sprintf("-DprocessDependencyManagement=%t", foundInDependencyManagement)}
	updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
	log.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
	output, err := mph.RunMvnCmd(updateVersionArgs)
	if err != nil {
		versionNotAvailableString := fmt.Sprintf(MavenVersionNotAvailableErrorFormat, fixedVersion)
		// Replace Maven's 'version not available' error with more readable error message
		if strings.Contains(string(output), versionNotAvailableString) {
			err = fmt.Errorf("couldn't update %q to suggested fix version: %s", impactedPackage, versionNotAvailableString)
		}
	}
	return err
}

// Update properties that represent this package's version.
func (mph *MavenPackageHandler) updateProperties(depDetails *pomDependencyDetails, fixedVersion string) error {
	for _, property := range depDetails.properties {
		updatePropertyArgs := []string{
			"-U", "-B", "org.codehaus.mojo:versions-maven-plugin:set-property", "-Dproperty=" + property,
			"-DnewVersion=" + fixedVersion, "-DgenerateBackupPoms=false",
			fmt.Sprintf("-DprocessDependencies=%t", !depDetails.foundInDependencyManagement),
			fmt.Sprintf("-DprocessDependencyManagement=%t", depDetails.foundInDependencyManagement)}
		updatePropertyCmd := fmt.Sprintf("mvn %s", strings.Join(updatePropertyArgs, " "))
		log.Debug(fmt.Sprintf("Running '%s'", updatePropertyCmd))
		if _, err := mph.RunMvnCmd(updatePropertyArgs); err != nil { // #nosec G204
			return fmt.Errorf("failed updating %s property: %s", property, err.Error())
		}
	}
	return nil
}
