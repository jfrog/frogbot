package packageupdaters

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/frogbot/v2/utils"
)

func TestMavenUpdateRegularDependency(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "maven-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	updater := &MavenPackageUpdater{}
	vulnDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion: "1.1.5",
		IsDirectDependency:    true,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Technology: techutils.Maven,
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "org.jfrog.filespecs:file-specs-java",
				Components: []formats.ComponentRow{
					{Location: &formats.Location{File: "pom.xml"}},
				},
			},
		},
	}

	err = updater.UpdateDependency(vulnDetails)
	assert.NoError(t, err)

	modifiedPom, err := os.ReadFile("pom.xml")
	assert.NoError(t, err)
	assert.Contains(t, string(modifiedPom), "<version>1.1.5</version>")
	assert.NotContains(t, string(modifiedPom), "<version>1.1.1</version>")
}

func TestMavenUpdateDependencyManagement(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "maven-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	updater := &MavenPackageUpdater{}
	vulnDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion: "2.15.0",
		IsDirectDependency:    true,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Technology: techutils.Maven,
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "com.fasterxml.jackson.core:jackson-core",
				Components: []formats.ComponentRow{
					{Location: &formats.Location{File: "pom.xml"}},
				},
			},
		},
	}

	err = updater.UpdateDependency(vulnDetails)
	assert.NoError(t, err)

	modifiedPom, err := os.ReadFile("pom.xml")
	assert.NoError(t, err)
	assert.Contains(t, string(modifiedPom), "<version>2.15.0</version>")
	assert.NotContains(t, string(modifiedPom), "<version>2.13.4</version>")
}

func TestMavenUpdatePropertyVersion(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "maven-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))

	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>test</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
    
    <properties>
        <jackson.version>2.9.8</jackson.version>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson.version}</version>
        </dependency>
    </dependencies>
</project>`

	assert.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pom.xml"), []byte(pomContent), 0644))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	updater := &MavenPackageUpdater{}
	vulnDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion: "2.13.0",
		IsDirectDependency:    true,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Technology: techutils.Maven,
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "com.fasterxml.jackson.core:jackson-databind",
				Components: []formats.ComponentRow{
					{Location: &formats.Location{File: "pom.xml"}},
				},
			},
		},
	}

	err = updater.UpdateDependency(vulnDetails)
	assert.NoError(t, err)

	modifiedPom, err := os.ReadFile("pom.xml")
	assert.NoError(t, err)
	assert.Contains(t, string(modifiedPom), "2.13.0")
	assert.NotContains(t, string(modifiedPom), "2.9.8")
}

func TestMavenUpdateParentPOM(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "maven-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))

	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.5.0</version>
    </parent>
    
    <groupId>test</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
</project>`

	assert.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pom.xml"), []byte(pomContent), 0644))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	updater := &MavenPackageUpdater{}
	vulnDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion: "2.7.0",
		IsDirectDependency:    true,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Technology: techutils.Maven,
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "org.springframework.boot:spring-boot-starter-parent",
				Components: []formats.ComponentRow{
					{Location: &formats.Location{File: "pom.xml"}},
				},
			},
		},
	}

	err = updater.UpdateDependency(vulnDetails)
	assert.NoError(t, err)

	modifiedPom, err := os.ReadFile("pom.xml")
	assert.NoError(t, err)
	assert.Contains(t, string(modifiedPom), "<version>2.7.0</version>")
	assert.NotContains(t, string(modifiedPom), "<version>2.5.0</version>")
}

func TestMavenDependencyNotFound(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packagehandlers")
	currDir, err := os.Getwd()
	assert.NoError(t, err)
	tmpDir, err := os.MkdirTemp("", "maven-test-*")
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}()

	assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
	assert.NoError(t, os.Chdir(tmpDir))
	defer func() {
		assert.NoError(t, os.Chdir(currDir))
	}()

	updater := &MavenPackageUpdater{}
	vulnDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion: "1.0.0",
		IsDirectDependency:    true,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Technology: techutils.Maven,
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "com.nonexistent:package",
				Components: []formats.ComponentRow{
					{Location: &formats.Location{File: "pom.xml"}},
				},
			},
		},
	}

	err = updater.UpdateDependency(vulnDetails)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMavenIndirectDependencyNotSupported(t *testing.T) {
	updater := &MavenPackageUpdater{}
	vulnDetails := &utils.VulnerabilityDetails{
		SuggestedFixedVersion: "1.0.0",
		IsDirectDependency:    false,
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Technology: techutils.Maven,
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				ImpactedDependencyName: "org.springframework:spring-core",
				Components: []formats.ComponentRow{
					{Location: &formats.Location{File: "pom.xml"}},
				},
			},
		},
	}

	err := updater.UpdateDependency(vulnDetails)
	assert.Error(t, err)

	var unsupportedErr *utils.ErrUnsupportedFix
	assert.True(t, errors.As(err, &unsupportedErr))
	assert.Equal(t, utils.IndirectDependencyFixNotSupported, unsupportedErr.ErrorType)
}
