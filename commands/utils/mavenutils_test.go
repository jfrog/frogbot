package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDependenciesFromPomXmlSingleDependency(t *testing.T) {
	testCases := []string{`<dependency> 
	<groupId>org.apache.commons</groupId>
	<artifactId>commons-email</artifactId>
	<version>1.1</version>
	<scope>compile</scope>
</dependency>`,
		`<dependency> 
	<groupId> 	org.apache.commons</groupId>
	<artifactId>commons-email	 </artifactId>
	<version>  1.1  </version>
	<scope> compile		</scope>
</dependency>`,
	}

	for _, testCase := range testCases {
		result, err := getDependenciesFromPomXml([]byte(testCase))
		assert.NoError(t, err)

		assert.Len(t, result, 1)
		assert.Equal(t, "org.apache.commons", result[0].GroupId)
		assert.Equal(t, "commons-email", result[0].ArtifactId)
		assert.Equal(t, "1.1", result[0].Version)
	}
}

func TestGetDependenciesFromPomXmlMultiDependency(t *testing.T) {
	testCases := []string{`<dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-email</artifactId>
            <version>1.1</version>
            <scope>compile</scope>
        </dependency>
        <dependency>
            <groupId>org.codehaus.plexus</groupId>
            <artifactId>plexus-utils</artifactId>
            <version>1.5.1</version>
        </dependency>
	</dependencies>`,
		`<dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-email</artifactId>
            <version>1.1</version><scope>compile</scope>
        </dependency>

		some-xml-tags

        <dependency>
            <groupId>org.codehaus.plexus</groupId>
        <artifactId>plexus-utils</artifactId>
            	<version>1.5.1</version>
        </dependency></dependencies>`,
	}

	for _, testCase := range testCases {
		result, err := getDependenciesFromPomXml([]byte(testCase))
		assert.NoError(t, err)

		assert.Len(t, result, 2)
		assert.Equal(t, "org.apache.commons", result[0].GroupId)
		assert.Equal(t, "commons-email", result[0].ArtifactId)
		assert.Equal(t, "1.1", result[0].Version)

		assert.Equal(t, "org.codehaus.plexus", result[1].GroupId)
		assert.Equal(t, "plexus-utils", result[1].ArtifactId)
		assert.Equal(t, "1.5.1", result[1].Version)
	}
}

func TestGetMavenModuleFromPomXml(t *testing.T) {
	testCases := []string{`<module>multi-1</module>`, ` <module>  	multi-1 </module>	`}
	for _, testCase := range testCases {
		modules := getMavenModuleFromPomXml([]byte(testCase))
		assert.ElementsMatch(t, modules, []string{"multi-1"})
	}
}

func TestGetMavenModuleFromPomXmlMultiModules(t *testing.T) {
	testCases := []string{`<module>multi-1</module><module>multi-2</module>`,
		`<module>multi-1</module>	some-xml-tags  <module>multi-2</module>`}
	for _, testCase := range testCases {
		modules := getMavenModuleFromPomXml([]byte(testCase))
		assert.ElementsMatch(t, modules, []string{"multi-1", "multi-2"})
	}
}
