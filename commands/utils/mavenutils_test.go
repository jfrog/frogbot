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
	testCases := []string{`
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/maven-v4_0_0.xsd">
<dependencies>
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
	</dependencies>
</project>`,
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

func TestGetPluginsFromPomXml(t *testing.T) {
	testCase :=
		`<project>
			<build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-source-plugin</artifactId>
            </plugin>
            <plugin>
                <groupId>com.github.spotbugs</groupId>
                <artifactId>spotbugs-maven-plugin</artifactId>
                <version>4.5.3.0</version>
                <configuration>
                    <excludeFilterFile>spotbugs-security-exclude.xml</excludeFilterFile>
                    <plugins>
                        <plugin>
                            <groupId>com.h3xstream.findsecbugs</groupId>
                            <artifactId>findsecbugs-plugin</artifactId>
                            <version>1.12.0</version>
                        </plugin>
                    </plugins>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>2.22.1</version>
                <configuration>
                    <systemPropertyVariables>
                        <!--This will disable JenkinsRule timeout-->
                        <maven.surefire.debug>true</maven.surefire.debug>
                    </systemPropertyVariables>
                    <excludes>
                        <exclude>**/InjectedTest.java</exclude>
                        <exclude>**/*ITest.java</exclude>
                    </excludes>
                </configuration>
            </plugin>
        </plugins>
    </build>
	</project>
		`
	plugins, err := getDependenciesFromPomXml([]byte(testCase))
	assert.NoError(t, err)
	assert.Equal(t, "org.apache.maven.plugins", plugins[0].GroupId)
	assert.Equal(t, "maven-source-plugin", plugins[0].ArtifactId)
	assert.Equal(t, "com.github.spotbugs", plugins[1].GroupId)
	assert.Equal(t, "spotbugs-maven-plugin", plugins[1].ArtifactId)
	assert.Equal(t, "4.5.3.0", plugins[1].Version)
	assert.Equal(t, "com.h3xstream.findsecbugs", plugins[2].GroupId)
	assert.Equal(t, "findsecbugs-plugin", plugins[2].ArtifactId)
	assert.Equal(t, "1.12.0", plugins[2].Version)
	assert.Equal(t, "org.apache.maven.plugins", plugins[3].GroupId)
	assert.Equal(t, "maven-surefire-plugin", plugins[3].ArtifactId)
	assert.Equal(t, "2.22.1", plugins[3].Version)
}
