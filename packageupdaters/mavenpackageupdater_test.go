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

func TestMavenUpdateDependency(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	propertyPOM := `<?xml version="1.0" encoding="UTF-8"?>
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

	parentPOM := `<?xml version="1.0" encoding="UTF-8"?>
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

	testCases := []struct {
		name               string
		customPOM          string // if non-empty, overwrites pom.xml after copying testdata
		vulnDetails        *utils.VulnerabilityDetails
		expectedContains   []string
		expectedNotContain []string
	}{
		{
			name: "RegularDependency",
			vulnDetails: &utils.VulnerabilityDetails{
				SuggestedFixedVersion: "1.1.5",
				IsDirectDependency:    true,
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					Technology: techutils.Maven,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "org.jfrog.filespecs:file-specs-java",
						Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "pom.xml"}}}},
					},
				},
			},
			expectedContains:   []string{"<version>1.1.5</version>"},
			expectedNotContain: []string{"<version>1.1.1</version>"},
		},
		{
			name: "DependencyManagement",
			vulnDetails: &utils.VulnerabilityDetails{
				SuggestedFixedVersion: "2.15.0",
				IsDirectDependency:    true,
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					Technology: techutils.Maven,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "com.fasterxml.jackson.core:jackson-core",
						Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "pom.xml"}}}},
					},
				},
			},
			expectedContains:   []string{"<version>2.15.0</version>"},
			expectedNotContain: []string{"<version>2.13.4</version>"},
		},
		{
			name:      "PropertyVersion",
			customPOM: propertyPOM,
			vulnDetails: &utils.VulnerabilityDetails{
				SuggestedFixedVersion: "2.13.0",
				IsDirectDependency:    true,
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					Technology: techutils.Maven,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "com.fasterxml.jackson.core:jackson-databind",
						Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "pom.xml"}}}},
					},
				},
			},
			expectedContains:   []string{"2.13.0"},
			expectedNotContain: []string{"2.9.8"},
		},
		{
			name:      "ParentPOM",
			customPOM: parentPOM,
			vulnDetails: &utils.VulnerabilityDetails{
				SuggestedFixedVersion: "2.7.0",
				IsDirectDependency:    true,
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					Technology: techutils.Maven,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "org.springframework.boot:spring-boot-starter-parent",
						Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "pom.xml"}}}},
					},
				},
			},
			expectedContains:   []string{"<version>2.7.0</version>"},
			expectedNotContain: []string{"<version>2.5.0</version>"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "maven-test-*")
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()

			assert.NoError(t, biutils.CopyDir(testProjectPath, tmpDir, true, nil))
			if tc.customPOM != "" {
				assert.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pom.xml"), []byte(tc.customPOM), 0644))
			}
			assert.NoError(t, os.Chdir(tmpDir))
			defer func() {
				assert.NoError(t, os.Chdir(currDir))
			}()

			updater := &MavenPackageUpdater{}
			err = updater.UpdateDependency(tc.vulnDetails)
			assert.NoError(t, err)

			modifiedPom, err := os.ReadFile("pom.xml")
			assert.NoError(t, err)
			content := string(modifiedPom)
			for _, s := range tc.expectedContains {
				assert.Contains(t, content, s)
			}
			for _, s := range tc.expectedNotContain {
				assert.NotContains(t, content, s)
			}
		})
	}
}

func TestMavenUpdateDependencyErrors(t *testing.T) {
	testProjectPath := filepath.Join("..", "testdata", "packageupdaters")
	currDir, err := os.Getwd()
	assert.NoError(t, err)

	testCases := []struct {
		name        string
		vulnDetails *utils.VulnerabilityDetails
		useTestData bool
		assertErr   func(t *testing.T, err error)
	}{
		{
			name: "DependencyNotFound",
			vulnDetails: &utils.VulnerabilityDetails{
				SuggestedFixedVersion: "1.0.0",
				IsDirectDependency:    true,
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					Technology: techutils.Maven,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "com.nonexistent:package",
						Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "pom.xml"}}}},
					},
				},
			},
			useTestData: true,
			assertErr: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "com.nonexistent:package")
			},
		},
		{
			name: "IndirectDependencyNotSupported",
			vulnDetails: &utils.VulnerabilityDetails{
				SuggestedFixedVersion: "1.0.0",
				IsDirectDependency:    false,
				VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
					Technology: techutils.Maven,
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						ImpactedDependencyName: "org.springframework:spring-core",
						Components:             []formats.ComponentRow{{Evidences: []formats.Location{{File: "pom.xml"}}}},
					},
				},
			},
			useTestData: false,
			assertErr: func(t *testing.T, err error) {
				assert.Error(t, err)
				var unsupportedErr *utils.ErrUnsupportedFix
				assert.True(t, errors.As(err, &unsupportedErr))
				assert.Equal(t, utils.IndirectDependencyFixNotSupported, unsupportedErr.ErrorType)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.useTestData {
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
			}
			updater := &MavenPackageUpdater{}
			err := updater.UpdateDependency(tc.vulnDetails)
			tc.assertErr(t, err)
		})
	}
}
