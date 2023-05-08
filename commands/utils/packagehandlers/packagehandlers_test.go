package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestFixVersionInfo_UpdateFixVersion(t *testing.T) {
	type testCase struct {
		fixVersionInfo utils.FixVersionInfo
		newFixVersion  string
		expectedOutput string
	}

	testCases := []testCase{
		{fixVersionInfo: utils.FixVersionInfo{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.2.4", expectedOutput: "1.2.4"},
		{fixVersionInfo: utils.FixVersionInfo{FixVersion: "1.2.3", PackageType: "pkg", DirectDependency: true}, newFixVersion: "1.0.4", expectedOutput: "1.2.3"},
	}

	for _, tc := range testCases {
		t.Run(tc.expectedOutput, func(t *testing.T) {
			tc.fixVersionInfo.UpdateFixVersionIfMax(tc.newFixVersion)
			assert.Equal(t, tc.expectedOutput, tc.fixVersionInfo.FixVersion)
		})
	}
}

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
		result, err := getMavenDependencies([]byte(testCase))
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
		result, err := getMavenDependencies([]byte(testCase))
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
	plugins, err := getMavenDependencies([]byte(testCase))
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

func TestGetDependenciesFromDependencyManagement(t *testing.T) {
	testCase := `
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/maven-v4_0_0.xsd">
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>io.jenkins.tools.bom</groupId>
                <artifactId>bom-2.346.x</artifactId>
                <version>1607.va_c1576527071</version>
                <scope>import</scope>
                <type>pom</type>
            </dependency>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-core</artifactId>
                <version>2.13.4</version>
            </dependency>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>2.13.4.2</version>
            </dependency>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-annotations</artifactId>
                <version>2.13.4</version>
            </dependency>
            <dependency>
                <groupId>org.apache.httpcomponents</groupId>
                <artifactId>httpcore</artifactId>
                <version>4.4.15</version>
            </dependency>
            <dependency>
                <groupId>org.jenkins-ci.plugins.workflow</groupId>
                <artifactId>workflow-durable-task-step</artifactId>
                <version>1190.vc93d7d457042</version>
                <scope>test</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>
`
	dependencies, err := getMavenDependencies([]byte(testCase))
	assert.NoError(t, err)
	assert.Len(t, dependencies, 6)
	for _, dependency := range dependencies {
		assert.True(t, dependency.foundInDependencyManagement)
	}
}

func TestMavenGavReader(t *testing.T) {
	mvnHandler := &MavenPackageHandler{}
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	assert.NoError(t, fileutils.CopyDir(filepath.Join("..", "..", "testdata", "projects", "maven"), tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()
	// Test installMavenGavReader
	assert.NoError(t, mvnHandler.installMavenGavReader())
	assert.True(t, mvnHandler.isMavenGavReaderInstalled)
	// Test getProjectPoms using the maven-gav-reader plugin
	assert.NoError(t, mvnHandler.getProjectPoms())
	assert.Len(t, mvnHandler.pomPaths, 2)
}

func TestUpdatePackageVersion(t *testing.T) {
	testProjectPath := filepath.Join("..", "..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	assert.NoError(t, fileutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()
	testCases := []struct {
		impactedPackage             string
		fixedVersion                string
		foundInDependencyManagement bool
	}{
		{impactedPackage: "org.jfrog.filespecs:file-specs-java", fixedVersion: "1.1.2"},
		{impactedPackage: "com.fasterxml.jackson.core:jackson-core", fixedVersion: "2.15.0", foundInDependencyManagement: true},
		{impactedPackage: "org.apache.httpcomponents:httpcore", fixedVersion: "4.4.16", foundInDependencyManagement: true},
	}
	mvnHandler := &MavenPackageHandler{}
	for _, test := range testCases {
		assert.NoError(t, mvnHandler.updatePackageVersion(test.impactedPackage, test.fixedVersion, test.foundInDependencyManagement))
	}
	modifiedPom, err := os.ReadFile("pom.xml")
	assert.NoError(t, err)
	for _, test := range testCases {
		assert.Contains(t, fmt.Sprintf("<version>%s</version>", string(modifiedPom)), test.fixedVersion)
	}
}

func TestUpdatePropertiesVersion(t *testing.T) {
	testProjectPath := filepath.Join("..", "..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	assert.NoError(t, fileutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()
	mvnHandler := &MavenPackageHandler{}
	assert.NoError(t, mvnHandler.updateProperties(&pomDependencyDetails{properties: []string{"buildinfo.version"}}, "2.39.9"))
	modifiedPom, err := os.ReadFile("pom.xml")
	assert.NoError(t, err)
	assert.Contains(t, fmt.Sprintf("%s", string(modifiedPom)), "2.39.9")
}
