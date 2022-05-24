package utils

import (
	"encoding/xml"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

func GetVersionProperties(projectPath string, depToPropertyMap map[string][]string) error {
	contentBytes, err := ioutil.ReadFile(filepath.Join(projectPath, "pom.xml")) // #nosec G304
	if err != nil {
		return err
	}
	dependenciesPattern := "(<dependency>(.|\\s)*?<\\/dependency>)|(<plugin>(.|\\s)*?<\\/plugin>)"
	dependenciesRegexp, err := regexp.Compile(dependenciesPattern)
	if err != nil {
		return err
	}
	dependencyStrings := dependenciesRegexp.FindAll(contentBytes, -1)
	for _, depStr := range dependencyStrings {
		dep := &mavenDependency{}
		err = xml.Unmarshal(depStr, dep)
		if err != nil {
			return err
		}
		depName := dep.GroupId + ":" + dep.ArtifactId
		if _, exist := depToPropertyMap[depName]; !exist {
			depToPropertyMap[depName] = []string{}
		}
		if strings.HasPrefix(dep.Version, "${") {
			depToPropertyMap[depName] = append(depToPropertyMap[dep.GroupId+":"+dep.ArtifactId], strings.TrimPrefix(strings.TrimSuffix(dep.Version, "}"), "${"))
		}
	}

	modulePattern := "<module>(.|\\s)*?<\\/module>"
	moduleRegexp, err := regexp.Compile(modulePattern)
	if err != nil {
		return err
	}
	moduleStrings := moduleRegexp.FindAllString(string(contentBytes), -1)
	for _, moduleStr := range moduleStrings {
		modulePath := strings.TrimPrefix(strings.TrimSuffix(moduleStr, "</module>"), "<module>")
		modulePath = strings.TrimSpace(modulePath)
		err = GetVersionProperties(filepath.Join(projectPath, modulePath), depToPropertyMap)
		if err != nil {
			return err
		}
	}
	return nil
}

type mavenDependency struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}
