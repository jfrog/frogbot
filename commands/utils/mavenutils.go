package utils

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const modulePattern = "<module>(\\S|\\s)*?<\\/module>"

var moduleRegexp = regexp.MustCompile(modulePattern)

type gavCoordinate struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
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
	Dependencies []mavenDependency `xml:"dependencies>dependency"`
	Plugins      []mavenPlugin     `xml:"build>plugins>plugin"`
}

func (md *mavenDependency) collectMavenDependencies() []gavCoordinate {
	var result []gavCoordinate
	if !md.gavCoordinate.isEmpty() {
		result = append(result, *md.gavCoordinate.trimSpaces())
	}
	for _, dependency := range md.Dependencies {
		result = append(result, dependency.collectMavenDependencies()...)
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
	if !mp.gavCoordinate.isEmpty() {
		result = append(result, *mp.gavCoordinate.trimSpaces())
	}
	for _, plugin := range mp.NestedPlugins {
		result = append(result, plugin.collectMavenPlugins()...)
	}
	return result
}

// GetVersionProperties collects a map of the direct dependencies in the projectPath pom.xml file.
// If the version of a dependency is set in another property section, it is added as its value in the map.
func GetVersionProperties(projectPath string, depToPropertyMap map[string][]string) error {
	contentBytes, err := os.ReadFile(filepath.Join(projectPath, "pom.xml")) // #nosec G304
	if err != nil {
		return err
	}
	mavenDependencies, err := getDependenciesFromPomXml(contentBytes)
	if err != nil {
		return err
	}
	for _, dependency := range mavenDependencies {
		if dependency.Version == "" {
			continue
		}
		depName := fmt.Sprintf("%s:%s", dependency.GroupId, dependency.ArtifactId)
		if _, exist := depToPropertyMap[depName]; !exist {
			depToPropertyMap[depName] = []string{}
		}
		if strings.HasPrefix(dependency.Version, "${") {
			depToPropertyMap[depName] = append(depToPropertyMap[depName], strings.TrimPrefix(strings.TrimSuffix(dependency.Version, "}"), "${"))
		}
	}

	for _, moduleStr := range getMavenModuleFromPomXml(contentBytes) {
		if err = GetVersionProperties(filepath.Join(projectPath, moduleStr), depToPropertyMap); err != nil {
			return err
		}
	}
	return nil
}

// Extract all dependencies from the input pom.xml
// pomXmlContent - The pom.xml content
func getDependenciesFromPomXml(pomXmlContent []byte) (result []gavCoordinate, err error) {
	var dependencies mavenDependency
	if err := xml.Unmarshal(pomXmlContent, &dependencies); err != nil {
		return result, err
	}
	result = append(result, dependencies.collectMavenDependencies()...)
	return result, err
}

// Extract all modules from pom.xml
// pomXmlContent - The pom.xml content
func getMavenModuleFromPomXml(pomXmlContent []byte) []string {
	var results []string
	moduleStrings := moduleRegexp.FindAllString(string(pomXmlContent), -1)
	for _, moduleStr := range moduleStrings {
		modulePath := strings.TrimPrefix(strings.TrimSuffix(moduleStr, "</module>"), "<module>")
		results = append(results, strings.TrimSpace(modulePath))
	}
	return results
}
