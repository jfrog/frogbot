package utils

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	modulePattern       = "<module>(\\S|\\s)*?<\\/module>"
	dependenciesPattern = "(<dependency>(\\S|\\s)*?<\\/dependency>)|(<plugin>(\\S|\\s)*?<\\/plugin>)"
)

var (
	moduleRegexp       = regexp.MustCompile(modulePattern)
	dependenciesRegexp = regexp.MustCompile(dependenciesPattern)
)

func GetVersionProperties(projectPath string, depToPropertyMap map[string][]string) error {
	contentBytes, err := os.ReadFile(filepath.Join(projectPath, "pom.xml")) // #nosec G304
	if err != nil {
		return err
	}
	mavenDependencies, err := getDependenciesFromPomXml(contentBytes)
	if err != nil {
		return err
	}
	for _, mavenDependency := range mavenDependencies {
		depName := mavenDependency.GroupId + ":" + mavenDependency.ArtifactId
		if _, exist := depToPropertyMap[depName]; !exist {
			depToPropertyMap[depName] = []string{}
		}
		if strings.HasPrefix(mavenDependency.Version, "${") {
			depToPropertyMap[depName] = append(depToPropertyMap[mavenDependency.GroupId+":"+mavenDependency.ArtifactId], strings.TrimPrefix(strings.TrimSuffix(mavenDependency.Version, "}"), "${"))
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
func getDependenciesFromPomXml(pomXmlContent []byte) ([]mavenDependency, error) {
	var results []mavenDependency
	dependencyStrings := dependenciesRegexp.FindAll(pomXmlContent, -1)
	for _, depStr := range dependencyStrings {
		dep := &mavenDependency{}
		err := xml.Unmarshal(depStr, dep)
		if err != nil {
			return []mavenDependency{}, err
		}
		dep.trimSpaces()
		results = append(results, *dep)
	}
	return results, nil
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

type mavenDependency struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

func (md *mavenDependency) trimSpaces() {
	md.GroupId = strings.TrimSpace(md.GroupId)
	md.ArtifactId = strings.TrimSpace(md.ArtifactId)
	md.Version = strings.TrimSpace(md.Version)
}
