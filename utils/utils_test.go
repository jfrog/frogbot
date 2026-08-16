package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/frogbot/v3/utils/gitlabreport"
	"github.com/jfrog/frogbot/v3/utils/issues"
	"github.com/jfrog/frogbot/v3/utils/outputwriter"
)

const (
	dependencySubmissionTestOwner    = "dep-submission-test-owner"
	dependencySubmissionTestRepo     = "dep-submission-test-repo"
	dependencySubmissionTestJob      = "test-job-123"
	dependencySubmissionTestWorkflow = "test-workflow"
	dependencySubmissionTestSha      = "abc123def456"
)

func TestConvertSarifPathsToRelativeServices(t *testing.T) {
	issuesCollection := &issues.ScansIssuesCollection{
		ServicesVulnerabilities: []formats.SourceCodeRow{{
			Location: formats.Location{File: filepath.Join("tmp", "wd", "service.yaml")},
		}},
		ServicesViolations: []formats.SourceCodeRow{{
			Location: formats.Location{File: filepath.Join("tmp", "wd", "api.yaml")},
		}},
	}

	ConvertSarifPathsToRelative(issuesCollection, filepath.Join("tmp", "wd"))

	assert.Equal(t, "service.yaml", issuesCollection.ServicesVulnerabilities[0].Location.File)
	assert.Equal(t, "api.yaml", issuesCollection.ServicesViolations[0].Location.File)
}

func TestChdir(t *testing.T) {
	originCwd, err := os.Getwd()
	assert.NoError(t, err)

	restoreDir, err := Chdir("..")
	assert.NoError(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, filepath.Dir(originCwd), cwd)

	assert.NoError(t, restoreDir())
	cwd, err = os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, originCwd, cwd)
}

func TestChdirErr(t *testing.T) {
	originCwd, err := os.Getwd()
	assert.NoError(t, err)

	_, err = Chdir("not-existed")
	assert.Error(t, err)

	cwd, err := os.Getwd()
	assert.NoError(t, err)
	assert.Equal(t, originCwd, cwd)
}

func TestMd5Hash(t *testing.T) {
	tests := []struct {
		values       []string
		expectedHash string
	}{
		{[]string{"frogbot", "dev", "gopkg.in/yaml.v3", "3.0.0"},
			"d61bde82dc594e5ccc5a042fe224bf7c"},

		{[]string{"frogbot", "master", "gopkg.in/yaml.v3", "3.0.0"},
			"41405528994061bd108e3bbd4c039a03"},

		{[]string{"frogbot", "master", "gopkg.in/yaml.v3", "4.0.0"},
			"54d9e69ea1cba0c009445ad94778c083"},

		{[]string{"frogbot", "master", "go", "1.17"},
			"cedc1e5462e504fc992318d24e343e48"},

		{[]string{"frogbot", "master", "go", "17.1"},
			"67c768266553d80deb21fe6e2e9ec652"},

		{[]string{"frogbot", "frogbot-Go-golang.org/x/crypto-0.0.0-20220314234659-1baeb1ce4c0b", "golang.org/x/crypto", "0.0.0-20220314234659-1baeb1ce4c0b"},
			"a7f1c0ffb51035f860521ce11ac38288"},

		{[]string{"frogbot"},
			"99990025ad24adf5d780bbed740a2868"},

		{[]string{""},
			"d41d8cd98f00b204e9800998ecf8427e"},
	}

	for _, test := range tests {
		t.Run(test.expectedHash, func(t *testing.T) {
			hash, err := Md5Hash(test.values...)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedHash, hash)
		})
	}
}

func TestFixVersionsMapToMd5Hash(t *testing.T) {
	tests := []struct {
		vulnerabilities []*VulnerabilityDetails
		expectedHash    string
	}{
		{
			vulnerabilities: []*VulnerabilityDetails{
				{SuggestedFixedVersion: "1.2.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "pkg"}, Technology: techutils.Npm}, IsDirectDependency: false}},
			expectedHash: "5ce60f326e1d1e329b74e3310b34c969",
		}, {
			vulnerabilities: []*VulnerabilityDetails{
				{SuggestedFixedVersion: "5.2.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "pkg"}, Technology: techutils.Go}, IsDirectDependency: false},
				{SuggestedFixedVersion: "1.2.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "pkg2"}, Technology: techutils.Go}, IsDirectDependency: false}},
			expectedHash: "bf6e3f3204b8df46400785c60e9ff4c9",
		},
		{
			// The Same map with different order should be the same hash.
			vulnerabilities: []*VulnerabilityDetails{
				{SuggestedFixedVersion: "1.2.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "pkg2"}, Technology: techutils.Go}, IsDirectDependency: false},
				{SuggestedFixedVersion: "5.2.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "pkg"}, Technology: techutils.Go}, IsDirectDependency: false}},
			expectedHash: "bf6e3f3204b8df46400785c60e9ff4c9",
		}, {
			vulnerabilities: []*VulnerabilityDetails{
				{SuggestedFixedVersion: "0.2.33", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "myNuget"}, Technology: techutils.Nuget}, IsDirectDependency: false}},
			expectedHash: "ee2d3be06ca4fe53f6ab769e06d74702",
		},
	}
	for _, test := range tests {
		t.Run(test.expectedHash, func(t *testing.T) {
			vulnRows := ExtractVulnerabilitiesDetailsToRows(test.vulnerabilities)
			hash, err := VulnerabilityDetailsToMD5Hash(vulnRows...)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedHash, hash)
		})
	}
}

func TestGetRelativeWd(t *testing.T) {
	fullPath := filepath.Join("a", "b", "c", "d", "e")
	baseWd := filepath.Join("a", "b", "c")
	assert.Equal(t, filepath.Join("d", "e"), GetRelativeWd(fullPath, baseWd))

	baseWd = filepath.Join("a", "b", "c", "d", "e")
	assert.Equal(t, "", GetRelativeWd(fullPath, baseWd))
	fullPath += string(os.PathSeparator)
	assert.Equal(t, "", GetRelativeWd(fullPath, baseWd))
}

func TestIsDirectDependency(t *testing.T) {
	tests := []struct {
		impactPath    [][]formats.ComponentRow
		expected      bool
		expectedError bool
	}{
		{
			impactPath:    [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack2", Version: "1.2.3"}}},
			expected:      true,
			expectedError: false,
		}, {
			impactPath:    [][]formats.ComponentRow{{{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack21", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}, {{Name: "jfrog:pack1", Version: "1.2.3"}, {Name: "jfrog:pack22", Version: "1.2.3"}, {Name: "jfrog:pack3", Version: "1.2.3"}}},
			expected:      false,
			expectedError: false,
		}, {
			impactPath:    [][]formats.ComponentRow{},
			expected:      false,
			expectedError: true,
		},
	}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			isDirect, err := IsDirectDependency(test.impactPath)
			assert.Equal(t, test.expected, isDirect)
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatedBranchName(t *testing.T) {
	tests := []struct {
		branchName    string
		expectedError bool
		errorMessage  string
	}{
		{
			branchName:    "thi?s-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "thi^s-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "thi~s-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "this[]-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "this@-is-my-test",
			expectedError: true,
			errorMessage:  branchInvalidChars,
		}, {
			branchName:    "this is myt est ${BRANCH_NAME_HASH}",
			expectedError: false,
			errorMessage:  "",
		}, {
			branchName:    "(Feature)New branch ${BRANCH_NAME_HASH}",
			expectedError: false,
			errorMessage:  "",
		}, {
			branchName:    "(frogbot)(feature) ${BRANCH_NAME_HASH} my name",
			expectedError: false,
			errorMessage:  "",
		}, {
			branchName:    "-this_should_not_work_prefix",
			expectedError: true,
			errorMessage:  branchInvalidPrefix,
		}, {
			branchName:    "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur ullamcorper ultricies nisi. Nam eget dui. Etiam rhoncus. Maecenas tempus, tellus eget condimentum rhoncus, sem quam semper libero, sit amet adipiscing sem neque sed ipsum. Nam quam nunc, blandit vel, luctus pulvinar, hendrerit id, lorem. Maecenas nec odio et ante tincidunt tempus. Donec vitae sapien ut libero venenatis faucibus. Nullam quis ante. Etiam sit amet orci eget eros faucibus tincidunt. Duis leo. Sed fringilla mauris sit amet nibh. Donec sodales sagittis magna. Sed consequat, leo eget bibendum sodales, augue velit cursus nunc, quis gravida magna mi a libero. Fusce vulputate eleifend sapien. Vestibulum purus quam, scelerisque ut, mollis sed, nonummy id, metus. Nullam accumsan lorem in dui. Cras ultricies mi eu turpis hendrerit fringilla. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; In ac dui quis mi consectetuer lacinia. Nam pretium turpis et",
			expectedError: true,
			errorMessage:  branchInvalidLength,
		}, {
			branchName:    "",
			expectedError: false,
			errorMessage:  "",
		},
	}
	for _, test := range tests {
		t.Run("Branch Name: '"+test.branchName+"'", func(t *testing.T) {
			err := validateBranchName(test.branchName)
			if test.expectedError {
				assert.Error(t, err)
				assert.Equal(t, err.Error(), test.errorMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildServerConfigFile(t *testing.T) {
	preTestJFrogHome := os.Getenv(JfrogHomeDirEnv)
	defer func() {
		assert.NoError(t, os.Setenv(JfrogHomeDirEnv, preTestJFrogHome))
	}()
	assert.NoError(t, os.Setenv(JfrogHomeDirEnv, "path/to/nowhere"))
	server := &config.ServerDetails{
		Url:               "https://myserver.com",
		ArtifactoryUrl:    "https://myserver.com/artifactory",
		DistributionUrl:   "https://myserver.co/distribution",
		XrayUrl:           "https://myserver.com/xray",
		MissionControlUrl: "https://myserver.com/missioncontrol",
		PipelinesUrl:      "https://myserver.com/pipelines",
		AccessUrl:         "https://myserver.com/access",
		AccessToken:       "abcdefg1234",
	}
	expectedConfigurationFile :=
		`{
  "servers": [
    {
      "url": "https://myserver.com/",
      "artifactoryUrl": "https://myserver.com/artifactory/",
      "distributionUrl": "https://myserver.co/distribution/",
      "xrayUrl": "https://myserver.com/xray/",
      "missionControlUrl": "https://myserver.com/missioncontrol/",
      "pipelinesUrl": "https://myserver.com/pipelines/",
      "accessUrl": "https://myserver.com/access",
      "accessToken": "abcdefg1234",
      "serverId": "frogbot",
      "isDefault": true
    }
  ],
  "version": "6"
}`
	previousJFrogHome, currentJFrogHome, err := BuildServerConfigFile(server)
	assert.NoError(t, err)
	assert.Equal(t, "path/to/nowhere", previousJFrogHome)
	actualConfigurationFile, err := os.ReadFile(path.Join(currentJFrogHome, "jfrog-cli.conf.v6"))
	assert.NoError(t, err)
	assert.Equal(t, expectedConfigurationFile, string(actualConfigurationFile))
}

func TestExtractVunerabilitiesDetailsToRows(t *testing.T) {
	testCases := []struct {
		name         string
		vulnDetails  []*VulnerabilityDetails
		expectedRows []formats.VulnerabilityOrViolationRow
	}{
		{
			name:         "No Vulnerabilities",
			vulnDetails:  []*VulnerabilityDetails{},
			expectedRows: []formats.VulnerabilityOrViolationRow{},
		},
		{
			name:         "Single Vulnerability",
			vulnDetails:  []*VulnerabilityDetails{{VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{IssueId: "1"}}},
			expectedRows: []formats.VulnerabilityOrViolationRow{{IssueId: "1"}},
		},
		{
			name:         "Multiple Vulnerabilities",
			vulnDetails:  []*VulnerabilityDetails{{VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{IssueId: "1"}}, {VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{IssueId: "2"}}},
			expectedRows: []formats.VulnerabilityOrViolationRow{{IssueId: "1"}, {IssueId: "2"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualRows := ExtractVulnerabilitiesDetailsToRows(tc.vulnDetails)
			assert.ElementsMatch(t, tc.expectedRows, actualRows)
		})
	}
}

func TestNormalizeWhiteSpace(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{input: "hello  world", expected: "hello world"},
		{input: "hello     world", expected: "hello world"},
		{input: "  hello     world", expected: "hello world"},
		{input: "  hello     world  ", expected: "hello world"},
		{input: "  hello     world   a   ", expected: "hello world a"},
	}
	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			output := normalizeWhitespaces(tc.input)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestTechArrayToString(t *testing.T) {
	testCases := []struct {
		techArray []techutils.Technology
		separator string
		expected  string
	}{{
		techArray: []techutils.Technology{techutils.Maven, techutils.Go},
		separator: fixBranchTechSeparator, expected: "Maven-Go",
	}, {
		techArray: []techutils.Technology{techutils.Go},
		separator: fixBranchTechSeparator, expected: "Go",
	}, {
		techArray: []techutils.Technology{techutils.Go},
		separator: pullRequestTitleTechSeparator, expected: "Go",
	}, {
		techArray: []techutils.Technology{techutils.Go, techutils.Pip, techutils.Npm},
		separator: pullRequestTitleTechSeparator, expected: "Go,Pip,npm",
	}, {
		techArray: []techutils.Technology{techutils.Go, techutils.Pip, techutils.Npm},
		separator: fixBranchTechSeparator, expected: "Go-Pip-npm",
	}}
	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			output := techArrayToString(tc.techArray, tc.separator)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestIsUrlAccessible(t *testing.T) {
	testCases := []struct {
		name           string
		url            string
		expectedOutput bool
	}{
		{
			name:           "Accessible URL",
			url:            outputwriter.FrogbotRepoUrl,
			expectedOutput: true,
		},
		{
			name:           "Inaccessible URL",
			url:            "https://www.google.com/this-is-not-a-real-url",
			expectedOutput: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := isUrlAccessible(tc.url)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestUploadSbomSnapshotToGithubDependencyGraph(t *testing.T) {
	// Capture original environment variable values to ensure proper restoration in case of a failure mid-test
	originalEnvVars := map[string]string{
		utils.CurrentGithubWorkflowJobEnvVar:  os.Getenv(utils.CurrentGithubWorkflowJobEnvVar),
		utils.CurrentGithubWorkflowNameEnvVar: os.Getenv(utils.CurrentGithubWorkflowNameEnvVar),
		utils.CurrentGithubShaEnvVar:          os.Getenv(utils.CurrentGithubShaEnvVar),
	}
	defer func() {
		for key, value := range originalEnvVars {
			if value == "" {
				assert.NoError(t, os.Unsetenv(key))
			} else {
				assert.NoError(t, os.Setenv(key, value))
			}
		}
	}()

	testcases := []struct {
		name              string
		envVars           map[string]string
		scanResults       *results.SecurityCommandResults
		errorExpected     bool
		mockServerFactory func(t *testing.T, owner, repo string) *httptest.Server
	}{
		{
			name: "Successful Dependency Submission",
			envVars: map[string]string{
				utils.CurrentGithubWorkflowJobEnvVar:  dependencySubmissionTestJob,
				utils.CurrentGithubWorkflowNameEnvVar: dependencySubmissionTestWorkflow,
				utils.CurrentGithubShaEnvVar:          dependencySubmissionTestSha,
			},
			scanResults:       createTestSecurityCommandResults(),
			errorExpected:     false,
			mockServerFactory: CreateMockServerForDependencySubmission,
		},
		{
			name: "Missing env vars",
			envVars: map[string]string{
				utils.CurrentGithubWorkflowJobEnvVar:  dependencySubmissionTestJob,
				utils.CurrentGithubWorkflowNameEnvVar: "",
				utils.CurrentGithubShaEnvVar:          dependencySubmissionTestSha,
			},
			scanResults:       createTestSecurityCommandResults(),
			errorExpected:     true,
			mockServerFactory: CreateMockServerForDependencySubmission,
		},
		{
			name: "Empty scan results",
			envVars: map[string]string{
				utils.CurrentGithubWorkflowJobEnvVar:  dependencySubmissionTestJob,
				utils.CurrentGithubWorkflowNameEnvVar: dependencySubmissionTestWorkflow,
				utils.CurrentGithubShaEnvVar:          dependencySubmissionTestSha,
			},
			scanResults:       nil,
			errorExpected:     true,
			mockServerFactory: CreateMockServerForDependencySubmission,
		},
		{
			name: "API Error",
			envVars: map[string]string{
				utils.CurrentGithubWorkflowJobEnvVar:  dependencySubmissionTestJob,
				utils.CurrentGithubWorkflowNameEnvVar: dependencySubmissionTestWorkflow,
				utils.CurrentGithubShaEnvVar:          dependencySubmissionTestSha,
			},
			scanResults:       createTestSecurityCommandResults(),
			errorExpected:     true,
			mockServerFactory: CreateMockServerForDependencySubmissionError,
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			// Create mock server for this test case
			mockServer := test.mockServerFactory(t, dependencySubmissionTestOwner, dependencySubmissionTestRepo)
			defer mockServer.Close()

			// Create a mock VCS client that points to our mock server
			client, err := vcsclient.NewGitHubClient(vcsclient.VcsInfo{
				APIEndpoint: mockServer.URL,
				Token:       "test-token",
			}, &vcsutils.EmptyLogger{})
			assert.NoError(t, err)

			restoreEnv := SetEnvsAndAssertWithCallback(t, test.envVars)
			err = UploadSbomSnapshotToGithubDependencyGraph(dependencySubmissionTestOwner, dependencySubmissionTestRepo, test.scanResults, client, "main")
			if test.errorExpected {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			// Restore environment at the end of each iteration for immediate cleanup
			restoreEnv()
		})
	}
}

func TestUpdateFixVersionIfMax(t *testing.T) {
	type testCase struct {
		fixVersionInfo VulnerabilityDetails
		newFixVersion  string
		expectedOutput string
	}

	testCases := []testCase{
		{fixVersionInfo: VulnerabilityDetails{SuggestedFixedVersion: "1.2.3", IsDirectDependency: true}, newFixVersion: "1.2.4", expectedOutput: "1.2.4"},
		{fixVersionInfo: VulnerabilityDetails{SuggestedFixedVersion: "1.2.3", IsDirectDependency: true}, newFixVersion: "1.0.4", expectedOutput: "1.2.3"},
	}

	for _, tc := range testCases {
		t.Run(tc.expectedOutput, func(t *testing.T) {
			tc.fixVersionInfo.UpdateFixVersionIfMax(tc.newFixVersion)
			assert.Equal(t, tc.expectedOutput, tc.fixVersionInfo.SuggestedFixedVersion)
		})
	}
}

func createTestSecurityCommandResults() *results.SecurityCommandResults {
	// Create a simple BOM with components
	components := []cyclonedx.Component{
		{
			BOMRef:     "comp1",
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       "express",
			Version:    "4.18.2",
			PackageURL: "pkg:npm/express@4.18.2",
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{Location: "package.json"},
				},
			},
		},
		{
			BOMRef:     "comp2",
			Type:       cyclonedx.ComponentTypeLibrary,
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{Location: "package.json"},
				},
			},
		},
	}

	dependencies := []cyclonedx.Dependency{
		{Ref: "comp1", Dependencies: &[]string{"comp2"}},
		{Ref: "comp2", Dependencies: &[]string{}},
	}

	bom := cyclonedx.NewBOM()
	bom.Components = &components
	bom.Dependencies = &dependencies

	// Create SecurityCommandResults with the BOM
	scanResults := &results.SecurityCommandResults{
		ResultsMetaData: results.ResultsMetaData{
			StartTime: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)},
		Targets: []*results.TargetResults{
			{
				ScanTarget: results.ScanTarget{
					Target: "test-target",
				},
				ScaResults: &results.ScaScanResults{
					Sbom: bom,
				},
			},
		},
	}

	return scanResults
}

func TestWriteScanResultsToGitlabDir(t *testing.T) {
	start := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name        string
		outputDir   func(t *testing.T) string
		scanResults *results.SecurityCommandResults
		wantErr     bool
		errContains string
		validate    func(t *testing.T, outputDir string)
	}{
		{
			name: "empty output dir",
			outputDir: func(t *testing.T) string {
				return ""
			},
			scanResults: createTestSecurityCommandResults(),
			wantErr:     true,
			errContains: "output directory is required",
		},
		{
			name: "nil scan results",
			outputDir: func(t *testing.T) string {
				return t.TempDir()
			},
			scanResults: nil,
			wantErr:     true,
			errContains: "scan results are required",
		},
		{
			name: "writes CycloneDX and GitLab dependency-scanning report",
			outputDir: func(t *testing.T) string {
				return t.TempDir()
			},
			scanResults: createTestSecurityCommandResults(),
			wantErr:     false,
			validate: func(t *testing.T, outputDir string) {
				cdxPath := filepath.Join(outputDir, cyclonedxOutputFilename)
				_, err := os.Stat(cdxPath)
				assert.NoError(t, err)

				gitlabPath := filepath.Join(outputDir, "gl-dependency-scanning-report.json")
				data, err := os.ReadFile(gitlabPath)
				assert.NoError(t, err)

				var report gitlabreport.DependencyScanningReport
				assert.NoError(t, json.Unmarshal(data, &report))
				assert.Equal(t, "15.2.4", report.Version)
				assert.Equal(t, "success", report.Scan.Status)
				assert.Equal(t, "dependency_scanning", report.Scan.Type)
				assert.Equal(t, FrogbotVersion, report.Scan.Analyzer.Version)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.outputDir(t)
			err := WriteScanResultsToGitlabDir(dir, tt.scanResults, start)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			assert.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, dir)
			}
		})
	}
}

func TestPrintScanResultsTable(t *testing.T) {
	const secretSnippet = "my-snippet-1234"

	tests := []struct {
		name                 string
		scanResults          *results.SecurityCommandResults
		showSecrets          bool
		expectSecretInOutput bool
	}{
		{
			name:        "nil scan results should not panic",
			scanResults: nil,
			showSecrets: true,
		},
		{
			name: "empty scan results should not panic",
			scanResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{},
			},
			showSecrets: true,
		},
		{
			name: "scan results should print without error",
			scanResults: &results.SecurityCommandResults{
				ResultsMetaData: results.ResultsMetaData{
					Entitlements:  results.Entitlements{Jas: true},
					ResultContext: results.ResultContext{IncludeVulnerabilities: true},
				},
				Targets: []*results.TargetResults{{
					ScanTarget: results.ScanTarget{Target: "test-target"},
					ScaResults: &results.ScaScanResults{
						DeprecatedXrayResults: []services.ScanResponse{{
							Vulnerabilities: []services.Vulnerability{
								{
									Cves:       []services.Cve{{Id: "CVE-2022-0001"}},
									Severity:   "High",
									Components: map[string]services.Component{"test-dep:1.0.0": {FixedVersions: []string{"1.0.1"}}},
								},
							},
						}},
					},
					JasResults: &results.JasScansResults{
						JasVulnerabilities: results.JasScanResults{
							SecretsScanResults: []*sarif.Run{
								sarifutils.CreateRunWithDummyResultAndRuleInformation(
									sarifutils.CreateResultWithLocations("Secret", "rule", "error",
										sarifutils.CreateLocation("index.js", 5, 6, 7, 8, secretSnippet),
									), "", "", nil, nil),
							},
						},
					},
				}},
			},
			showSecrets:          true,
			expectSecretInOutput: true,
		},
		{
			name: "secrets are hidden when not allowed",
			scanResults: &results.SecurityCommandResults{
				ResultsMetaData: results.ResultsMetaData{
					Entitlements:  results.Entitlements{Jas: true},
					ResultContext: results.ResultContext{IncludeVulnerabilities: true},
				},
				Targets: []*results.TargetResults{{
					ScanTarget: results.ScanTarget{Target: "test-target"},
					JasResults: &results.JasScansResults{
						JasVulnerabilities: results.JasScanResults{
							SecretsScanResults: []*sarif.Run{
								sarifutils.CreateRunWithDummyResultAndRuleInformation(
									sarifutils.CreateResultWithLocations("Secret", "rule", "error",
										sarifutils.CreateLocation("index.js", 5, 6, 7, 8, secretSnippet),
									), "", "", nil, nil),
							},
						},
					},
				}},
			},
			showSecrets:          false,
			expectSecretInOutput: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stdout = w

			assert.NotPanics(t, func() {
				PrintScanResultsTable(test.scanResults, test.showSecrets)
			})

			require.NoError(t, w.Close())
			os.Stdout = originalStdout
			capturedOutput, err := io.ReadAll(r)
			require.NoError(t, err)

			if test.expectSecretInOutput {
				assert.Contains(t, string(capturedOutput), secretSnippet)
			} else {
				assert.NotContains(t, string(capturedOutput), secretSnippet)
			}
		})
	}
}

func TestHideSecretsForPrinting(t *testing.T) {
	secretRun := &sarif.Run{}
	violationSecret := violationutils.JasViolation{}

	scanResults := &results.SecurityCommandResults{
		Targets: []*results.TargetResults{
			{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []*sarif.Run{secretRun},
					},
				},
			},
			// Target without JAS results, to make sure it is skipped without panicking.
			{},
		},
		Violations: &violationutils.Violations{
			Secrets: []violationutils.JasViolation{violationSecret},
		},
	}

	restore := hideSecretsForPrinting(scanResults)
	assert.Nil(t, scanResults.Targets[0].JasResults.JasVulnerabilities.SecretsScanResults)
	assert.Nil(t, scanResults.Violations.Secrets)

	restore()
	assert.Equal(t, []*sarif.Run{secretRun}, scanResults.Targets[0].JasResults.JasVulnerabilities.SecretsScanResults)
	assert.Equal(t, []violationutils.JasViolation{violationSecret}, scanResults.Violations.Secrets)
}

func TestPrintScanResultsTableResultsPlatformURL(t *testing.T) {
	const resultsURL = "https://example.jfrog.io/ui/xray/scans-list/git-repositories/test"
	originalLogger := log.GetLogger()
	t.Cleanup(func() {
		log.SetLogger(originalLogger)
	})

	testCases := []struct {
		name               string
		resultsPlatformURL string
		expectURL          bool
	}{
		{
			name:               "prints available URL",
			resultsPlatformURL: resultsURL,
			expectURL:          true,
		},
		{
			name:      "omits unavailable URL",
			expectURL: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			log.SetLogger(log.NewLogger(log.INFO, &output))
			scanResults := &results.SecurityCommandResults{
				ResultsMetaData: results.ResultsMetaData{
					ResultsPlatformUrl: testCase.resultsPlatformURL,
				},
				Targets: []*results.TargetResults{},
			}

			PrintScanResultsTable(scanResults, true)

			if testCase.expectURL {
				assert.Contains(t, output.String(), resultsURL)
				assert.Contains(t, output.String(), "You may view the scan results in the JFrog platform")
			} else {
				assert.NotContains(t, output.String(), "You may view the scan results in the JFrog platform")
			}
		})
	}
}
