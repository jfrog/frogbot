package packagehandlers

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	rtutils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	mvnutils "github.com/jfrog/jfrog-cli-core/v2/utils/mvn"
	"github.com/jfrog/jfrog-cli-core/v2/xray/audit/java"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
)

const mavenGavReader = "maven-gav-reader.jar"

var (
	//go:embed resources/maven-gav-reader.jar
	mavenGavReaderContent []byte
)

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
	contentBytes, err := os.ReadFile(pomPath) // #nosec G304
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
		if _, exist := mph.mavenDepToPropertyMap[depName]; !exist {
			mph.mavenDepToPropertyMap[depName] = pomDependencyDetails{foundInDependencyManagement: dependency.foundInDependencyManagement, currentVersion: dependency.Version}
		}
		if strings.HasPrefix(dependency.Version, "${") {
			trimmedVersion := strings.Trim(dependency.Version, "${}")
			if !slices.Contains(mph.mavenDepToPropertyMap[depName].properties, trimmedVersion) {
				mph.mavenDepToPropertyMap[depName] = pomDependencyDetails{
					properties:                  append(mph.mavenDepToPropertyMap[depName].properties, trimmedVersion),
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
		return result, err
	}
	result = append(result, dependencies.collectMavenDependencies(false)...)
	return result, err
}

type pomPath struct {
	PomPath string `json:"pomPath"`
}

type pomDependencyDetails struct {
	properties                  []string
	currentVersion              string
	foundInDependencyManagement bool
}

type MavenPackageHandler struct {
	CommonPackageHandler
	// mavenDepToPropertyMap holds a map of direct dependencies found in pom.xml.
	mavenDepToPropertyMap map[string]pomDependencyDetails
	// pomPaths holds the paths to all the pom.xml files that are related to the current project.
	pomPaths []pomPath
	// A flag that determines whether the maven-gav-reader.jar plugin should be installed or if it is already installed.
	isMavenGavReaderInstalled bool
	// The server details for Artifactory in case of an air-gapped environment.
	*config.ServerDetails
	// The remote repository in Artifactory to resolve dependencies from.
	depsRepo string
}

func (mph *MavenPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if err := mph.installMavenGavReader(); err != nil {
		return err
	}
	if err := mph.getProjectPoms(); err != nil {
		return err
	}
	// Get direct dependencies for each pom.xml file
	if mph.mavenDepToPropertyMap == nil {
		mph.mavenDepToPropertyMap = make(map[string]pomDependencyDetails)
	}
	for _, pp := range mph.pomPaths {
		if err := mph.fillDependenciesMap(pp.PomPath); err != nil {
			return err
		}
	}

	var depDetails pomDependencyDetails
	var exists bool
	// Check if the impacted package is a direct dependency
	impactedDependency := vulnDetails.ImpactedDependencyName
	if depDetails, exists = mph.mavenDepToPropertyMap[impactedDependency]; !exists {
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

func (mph *MavenPackageHandler) installMavenGavReader() (err error) {
	if mph.isMavenGavReaderInstalled {
		return nil
	}
	// Create maven-gav-reader plugin file and write the maven-gav-reader.jar content to it
	mavenGavReaderFile, err := os.CreateTemp("", fmt.Sprintf("*-%s", mavenGavReader))
	if err != nil {
		return fmt.Errorf("failed to create a temp %s file: \n%s", mavenGavReader, err.Error())
	}
	defer func() {
		closeError := mavenGavReaderFile.Close()
		deleteError := os.Remove(mavenGavReaderFile.Name())
		if err == nil {
			err = closeError
			if err == nil {
				err = deleteError
			}
		}
	}()
	gavReaderFolder := path.Dir(mavenGavReaderFile.Name())
	currentWd, err := os.Getwd()
	if err != nil {
		return
	}
	if err = os.Chdir(gavReaderFolder); err != nil {
		return err
	}
	defer func() {
		e := os.Chdir(currentWd)
		if err == nil {
			err = e
		}
	}()

	if _, err = mavenGavReaderFile.Write(mavenGavReaderContent); err != nil {
		return fmt.Errorf("failed writing content to the %s file: \n%s", mavenGavReader, err.Error())
	}
	// Install the plugin
	var output []byte
	installProperties := []string{"org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file", "-Dfile=" + mavenGavReaderFile.Name()}
	if output, err = exec.Command("mvn", installProperties...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install the maven-gav-reader plugin. Maven output: %s\n Error received:\n%s", string(output), err.Error())
	}
	mph.isMavenGavReaderInstalled = true
	return
}

func (mph *MavenPackageHandler) getProjectPoms() (err error) {
	// Check if we already scanned the project pom.xml locations
	if len(mph.pomPaths) > 0 {
		return nil
	}
	goals := []string{"com.jfrog.frogbot:maven-gav-reader:gav", "-q"}
	var readerOutput []byte
	if readerOutput, err = mph.runMvnCommand(goals); err != nil {
		return fmt.Errorf("failed to get project poms while running maven-gav-reader: \n%s\n%s", readerOutput, err.Error())
	}
	for _, jsonContent := range strings.Split(string(readerOutput), "\n") {
		if jsonContent == "" {
			continue
		}
		var pp pomPath
		// Escape backslashes in the pomPath field, to fix windows backslash parsing issues
		escapedContent := strings.ReplaceAll(jsonContent, `\`, `\\`)
		if err = json.Unmarshal([]byte(escapedContent), &pp); err != nil {
			return err
		}
		mph.pomPaths = append(mph.pomPaths, pp)
	}
	if len(mph.pomPaths) == 0 {
		return errors.New("couldn't find any pom.xml files in the current project'")
	}
	return
}

// Update the package version. Updates it only if the version is not a reference to a property.
func (mph *MavenPackageHandler) updatePackageVersion(impactedPackage, fixedVersion string, foundInDependencyManagement bool) (err error) {
	updateVersionArgs := []string{
		"-U", "-B", "org.codehaus.mojo:versions-maven-plugin:use-dep-version", "-Dincludes=" + impactedPackage,
		"-DdepVersion=" + fixedVersion, "-DgenerateBackupPoms=false",
		fmt.Sprintf("-DprocessDependencies=%t", !foundInDependencyManagement),
		fmt.Sprintf("-DprocessDependencyManagement=%t", foundInDependencyManagement)}
	updateVersionCmd := fmt.Sprintf("mvn %s", strings.Join(updateVersionArgs, " "))
	log.Debug(fmt.Sprintf("Running '%s'", updateVersionCmd))
	_, err = mph.runMvnCommand(updateVersionArgs)
	return
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
		if updatePropertyOutput, err := mph.runMvnCommand(updatePropertyArgs); err != nil { // #nosec G204
			return fmt.Errorf("failed updating %s property: %s\n%s", property, err.Error(), updatePropertyOutput)
		}
	}
	return nil
}

func (mph *MavenPackageHandler) runMvnCommand(goals []string) (readerOutput []byte, err error) {
	if mph.depsRepo == "" {
		if readerOutput, err = exec.Command("mvn", goals...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed running maven command: \n%s\n%s", readerOutput, err.Error())
		}
		return
	}
	// Run the mvn command with the Maven Build-Info Extractor to download dependencies from Artifactory.
	mvnProps := java.CreateMvnProps(mph.depsRepo, mph.ServerDetails)
	vConfig, err := rtutils.ReadMavenConfig("", mvnProps)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	mvnParams := mvnutils.NewMvnUtils().
		SetConfig(vConfig).
		SetGoals(goals).
		SetDisableDeploy(true).
		SetOutputWriter(&buf)
	if err = mvnutils.RunMvn(mvnParams); err != nil {
		return
	}

	readerOutput = make([]byte, buf.Len())
	_, err = io.ReadFull(&buf, readerOutput)
	return
}
