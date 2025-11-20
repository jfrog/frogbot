package scanpullrequest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

const (
	testSourceBranchName = "pr"
	testTargetBranchName = "master"
)

func TestScanResultsToIssuesCollection(t *testing.T) {
	allowedLicenses := []string{"MIT"}
	auditResults := &results.SecurityCommandResults{EntitledForJas: true, ResultContext: results.ResultContext{IncludeVulnerabilities: true}, Targets: []*results.TargetResults{{
		ScanTarget: results.ScanTarget{Target: "dummy"},
		ScaResults: &results.ScaScanResults{
			DeprecatedXrayResults: validations.NewMockScaResults(services.ScanResponse{
				Vulnerabilities: []services.Vulnerability{
					{Cves: []services.Cve{{Id: "CVE-2022-2122"}}, Severity: "High", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}},
					{Cves: []services.Cve{{Id: "CVE-2023-3122"}}, Severity: "Low", Components: map[string]services.Component{"Dep-2": {FixedVersions: []string{"1.2.2"}}}},
				},
				Licenses: []services.License{{Key: "Apache-2.0", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}}},
			}),
		},
		JasResults: &results.JasScansResults{
			ApplicabilityScanResults: validations.NewMockJasRuns(
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_CVE-2023-3122"),
					sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2022-2122", ""),
				),
			),
			JasVulnerabilities: results.JasScanResults{
				IacScanResults: validations.NewMockJasRuns(
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
						),
					),
				),
				SecretsScanResults: validations.NewMockJasRuns(
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("index.js", 5, 6, 7, 8, "access token exposed"),
						),
					),
				),
				SastScanResults: validations.NewMockJasRuns(
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
						),
					),
				),
			},
		},
	}}}
	expectedOutput := &issues.ScansIssuesCollection{
		ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				Applicable:    "Applicable",
				FixedVersions: []string{"1.2.3"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 21},
					ImpactedDependencyName: "Dep-1",
				},
				Cves: []formats.CveRow{{Id: "CVE-2022-2122", Applicability: &formats.Applicability{Status: "Applicable", ScannerDescription: "rule-msg", Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			},
			{
				Applicable:    "Not Applicable",
				FixedVersions: []string{"1.2.2"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 2},
					ImpactedDependencyName: "Dep-2",
				},
				Cves: []formats.CveRow{{Id: "CVE-2023-3122", Applicability: &formats.Applicability{Status: "Not Applicable", ScannerDescription: "rule-msg"}}},
			},
		},
		IacVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				ScannerInfo: formats.ScannerInfo{
					ScannerDescription: "rule-msg",
					RuleId:             "rule",
				},
				Finding: "Missing auto upgrade was detected",
				Location: formats.Location{
					File:        "file1",
					StartLine:   1,
					StartColumn: 10,
					EndLine:     2,
					EndColumn:   11,
					Snippet:     "aws-violation",
				},
			},
		},
		SecretsVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				ScannerInfo: formats.ScannerInfo{
					ScannerDescription: "rule-msg",
					RuleId:             "rule",
				},
				Finding: "Secret",
				Location: formats.Location{
					File:        "index.js",
					StartLine:   5,
					StartColumn: 6,
					EndLine:     7,
					EndColumn:   8,
					Snippet:     "access token exposed",
				},
			},
		},
		SastVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				ScannerInfo: formats.ScannerInfo{
					ScannerDescription: "rule-msg",
					RuleId:             "rule",
				},
				Finding: "XSS Vulnerability",
				Location: formats.Location{
					File:        "file1",
					StartLine:   1,
					StartColumn: 10,
					EndLine:     2,
					EndColumn:   11,
					Snippet:     "snippet",
				},
			},
		},
		LicensesViolations: []formats.LicenseViolationRow{
			{
				LicenseRow: formats.LicenseRow{
					LicenseKey: "Apache-2.0",
					ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "Medium",
							SeverityNumValue: 14,
						},
						ImpactedDependencyName: "Dep-1",
					},
				},
				ViolationContext: formats.ViolationContext{
					Watch: "jfrog_custom_license_violation",
				},
			},
		},
	}

	issuesRows, err := scanResultsToIssuesCollection(auditResults, allowedLicenses)

	if assert.NoError(t, err) {
		assert.ElementsMatch(t, expectedOutput.ScaVulnerabilities, issuesRows.ScaVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.IacVulnerabilities, issuesRows.IacVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.SecretsVulnerabilities, issuesRows.SecretsVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.SastVulnerabilities, issuesRows.SastVulnerabilities)
		assert.ElementsMatch(t, expectedOutput.LicensesViolations, issuesRows.LicensesViolations)
	}
}

func TestScanPullRequest(t *testing.T) {
	tests := []struct {
		testName             string
		projectName          string
		failOnSecurityIssues bool
	}{
		{
			testName:             "ScanPullRequest",
			projectName:          "test-proj",
			failOnSecurityIssues: true,
		},
		{
			testName:             "ScanPullRequestNoFail",
			projectName:          "test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestSubdir",
			projectName:          "test-proj-subdir",
			failOnSecurityIssues: true,
		},
		{
			testName:             "ScanPullRequestNoIssues",
			projectName:          "clean-test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestMultiWorkDir",
			projectName:          "multi-dir-test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestMultiWorkDirNoFail",
			projectName:          "multi-dir-test-proj",
			failOnSecurityIssues: true,
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			testScanPullRequest(t, test.projectName, test.failOnSecurityIssues)
		})
	}
}

func testScanPullRequest(t *testing.T, projectName string, failOnSecurityIssues bool) {
	configAggregator, client, cleanUp := preparePullRequestTest(t, projectName)
	defer cleanUp()

	// Run "frogbot scan pull request"
	var scanPullRequest ScanPullRequestCmd
	err := scanPullRequest.Run(configAggregator, client, utils.MockHasConnection())
	if failOnSecurityIssues {
		assert.EqualErrorf(t, err, SecurityIssueFoundErr, "Error should be: %v, got: %v", SecurityIssueFoundErr, err)
	} else {
		assert.NoError(t, err)
	}

	// Check env sanitize
	err = utils.SanitizeEnv()
	assert.NoError(t, err)
	utils.AssertSanitizedEnv(t)
}

func TestVerifyGitHubFrogbotEnvironment(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{Reviewers: []string{"froggy"}}, nil)
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.NoError(t, err)
}

func TestVerifyGitHubFrogbotEnvironmentNoEnv(t *testing.T) {
	// Redirect log to avoid negative output
	previousLogger := redirectLogOutputToNil()
	defer log.SetLogger(previousLogger)

	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{}, errors.New("404"))
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.ErrorContains(t, err, noGitHubEnvErr)
}

func TestVerifyGitHubFrogbotEnvironmentNoReviewers(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{}, nil)
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.ErrorContains(t, err, noGitHubEnvReviewersErr)
}

func TestVerifyGitHubFrogbotEnvironmentOnPrem(t *testing.T) {
	repoConfig := &utils.Repository{
		Params: utils.Params{Git: utils.Git{
			VcsInfo: vcsclient.VcsInfo{APIEndpoint: "https://acme.vcs.io"}},
		},
	}

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(&vcsclient.GitHubClient{}, repoConfig)
	assert.NoError(t, err)
}

func prepareConfigAndClient(t *testing.T, xrayVersion, xscVersion string, server *httptest.Server, serverParams coreconfig.ServerDetails, gitServerParams GitServerParams) (utils.RepoAggregator, vcsclient.VcsClient) {
	gitTestParams := &utils.Git{
		GitProvider: vcsutils.GitHub,
		RepoOwner:   gitServerParams.RepoOwner,
		VcsInfo: vcsclient.VcsInfo{
			Token:       "123456",
			APIEndpoint: server.URL,
		},
		PullRequestDetails: gitServerParams.prDetails,
	}
	utils.SetEnvAndAssert(t, map[string]string{utils.GitPullRequestIDEnv: fmt.Sprintf("%d", gitServerParams.prDetails.ID)})

	client, err := vcsclient.NewClientBuilder(vcsutils.GitLab).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	configAggregator, err := utils.BuildRepoAggregator(xrayVersion, xscVersion, client, gitTestParams, &serverParams, utils.ScanPullRequest)
	assert.NoError(t, err)

	return configAggregator, client
}

func TestDeletePreviousPullRequestMessages(t *testing.T) {
	repository := &utils.Repository{
		Params: utils.Params{
			Git: utils.Git{
				PullRequestDetails: vcsclient.PullRequestInfo{Target: vcsclient.BranchInfo{
					Repository: "repo",
					Owner:      "owner",
				}, ID: 17},
			},
		},
		OutputWriter: &outputwriter.StandardOutput{},
	}
	client := CreateMockVcsClient(t)

	testCases := []struct {
		name         string
		commentsOnPR []vcsclient.CommentInfo
		err          error
	}{
		{
			name: "Test with comment returned",
			commentsOnPR: []vcsclient.CommentInfo{
				{ID: 20, Content: outputwriter.GetBanner(outputwriter.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
			},
		},
		{
			name: "Test with no comment returned",
		},
		{
			name: "Test with error returned",
			err:  errors.New("error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with comment returned
			client.EXPECT().ListPullRequestComments(context.Background(), "owner", "repo", 17).Return(tc.commentsOnPR, tc.err)
			client.EXPECT().DeletePullRequestComment(context.Background(), "owner", "repo", 17, 20).Return(nil).AnyTimes()
			err := utils.DeleteExistingPullRequestComments(repository, client)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestDeletePreviousPullRequestReviewMessages(t *testing.T) {
	repository := &utils.Repository{
		Params: utils.Params{
			Git: utils.Git{
				PullRequestDetails: vcsclient.PullRequestInfo{Target: vcsclient.BranchInfo{
					Repository: "repo",
					Owner:      "owner",
				}, ID: 17},
			},
		},
		OutputWriter: &outputwriter.StandardOutput{},
	}
	client := CreateMockVcsClient(t)

	testCases := []struct {
		name         string
		commentsOnPR []vcsclient.CommentInfo
		err          error
	}{
		{
			name: "Test with comment returned",
			commentsOnPR: []vcsclient.CommentInfo{
				{ID: 20, Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "text \n table\n text text text", Created: time.Unix(3, 0)},
			},
		},
		{
			name: "Test with no comment returned",
		},
		{
			name: "Test with error returned",
			err:  errors.New("error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with comment returned
			client.EXPECT().ListPullRequestReviewComments(context.Background(), "", "", 17).Return(tc.commentsOnPR, tc.err)
			client.EXPECT().DeletePullRequestReviewComments(context.Background(), "", "", 17, tc.commentsOnPR).Return(nil).AnyTimes()
			err := utils.DeleteExistingPullRequestReviewComments(repository, 17, client)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// Set new logger with output redirection to a null logger. This is useful for negative tests.
// Caller is responsible to set the old log back.
func redirectLogOutputToNil() (previousLog log.Log) {
	previousLog = log.Logger
	newLog := log.NewLogger(log.ERROR, nil)
	newLog.SetOutputWriter(io.Discard)
	newLog.SetLogsWriter(io.Discard, 0)
	log.SetLogger(newLog)
	return previousLog
}

type TestResult struct {
	Sca     int
	Iac     int
	Secrets int
	Sast    int
}

func TestAuditDiffInPullRequest(t *testing.T) {
	tests := []struct {
		testName       string
		projectName    string
		expectedIssues TestResult
	}{
		{
			testName:    "Project with Jas issues (issues added removed and not changed)",
			projectName: "jas-diff-proj",
			expectedIssues: TestResult{
				Sca:  4,
				Sast: 1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			repoConfig, client, cleanUpTest := preparePullRequestTest(t, test.projectName)
			defer cleanUpTest()

			assert.Len(t, repoConfig, 1)
			issuesCollection, _, err := auditPullRequestAndReport(&repoConfig[0], client)
			assert.NoError(t, err)
			assert.NotNil(t, issuesCollection)
			assert.Len(t, issuesCollection.IacVulnerabilities, test.expectedIssues.Iac)
			assert.Len(t, issuesCollection.SecretsVulnerabilities, test.expectedIssues.Secrets)
			assert.GreaterOrEqual(t, len(issuesCollection.ScaVulnerabilities), test.expectedIssues.Sca)
			assert.GreaterOrEqual(t, len(issuesCollection.SastVulnerabilities), test.expectedIssues.Sast)
		})
	}
}

func TestToFailTaskStatus(t *testing.T) {
	tests := []struct {
		name             string
		setFailFlag      bool
		issuesCollection issues.ScansIssuesCollection
		failureExpected  bool
	}{
		{
			name:        "fail flag set to false and no violations with fail_pr",
			setFailFlag: false,
			issuesCollection: issues.ScansIssuesCollection{
				LicensesViolations: []formats.LicenseViolationRow{{
					LicenseRow: formats.LicenseRow{
						LicenseKey:  "license1",
						LicenseName: "license-name1",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
							Components: []formats.ComponentRow{
								{
									Name:    "vuln-pack-name3",
									Version: "1.0.0",
								},
							},
						},
					},
					ViolationContext: formats.ViolationContext{
						Watch:    "lic-watch",
						Policies: []string{"policy3"},
						FailPr:   false,
					},
				}},
			},
			failureExpected: false,
		},
		{
			name:        "fail flag set to true, sca vulnerability",
			setFailFlag: true,
			issuesCollection: issues.ScansIssuesCollection{
				ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							ImpactedDependencyName:    "impacted-name",
							ImpactedDependencyVersion: "1.0.0",
							SeverityDetails:           formats.SeverityDetails{Severity: "High"},
							Components: []formats.ComponentRow{
								{
									Name:    "vuln-pack-name1",
									Version: "1.0.0",
								},
								{
									Name:    "vuln-pack-name1",
									Version: "1.2.3",
								},
								{
									Name:    "vuln-pack-name2",
									Version: "1.2.3",
								},
							},
						},
						Cves: []formats.CveRow{{
							Id: "CVE-2021-1234",
							Applicability: &formats.Applicability{
								Status:             "Applicable",
								ScannerDescription: "scanner",
								Evidence: []formats.Evidence{
									{Reason: "reason", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet1"}},
									{Reason: "other reason", Location: formats.Location{File: "file2", StartLine: 5, StartColumn: 6, EndLine: 7, EndColumn: 8, Snippet: "snippet2"}},
								},
							},
						}},
						JfrogResearchInformation: &formats.JfrogResearchInformation{
							Remediation: "remediation",
						},
						Summary:    "summary",
						Applicable: "Applicable",
						IssueId:    "Xray-Id",
					},
					{
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							ImpactedDependencyName:    "impacted-name2",
							ImpactedDependencyVersion: "1.0.0",
							SeverityDetails:           formats.SeverityDetails{Severity: "Low"},
							Components: []formats.ComponentRow{
								{
									Name:    "vuln-pack-name3",
									Version: "1.0.0",
								},
							},
						},
						Cves: []formats.CveRow{{
							Id:            "CVE-1111-2222",
							Applicability: &formats.Applicability{Status: "Not Applicable"},
						}},
						Summary:    "other summary",
						Applicable: "Not Applicable",
						IssueId:    "Xray-Id2",
					},
				},
			},
			failureExpected: true,
		},
		{
			name:        "fail flag is set to false, fail_pr in licenses violation",
			setFailFlag: false,
			issuesCollection: issues.ScansIssuesCollection{
				LicensesViolations: []formats.LicenseViolationRow{{
					LicenseRow: formats.LicenseRow{
						LicenseKey:  "license1",
						LicenseName: "license-name1",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
							Components: []formats.ComponentRow{
								{
									Name:    "vuln-pack-name3",
									Version: "1.0.0",
								},
							},
						},
					},
					ViolationContext: formats.ViolationContext{
						Watch:    "lic-watch",
						Policies: []string{"policy3"},
						FailPr:   true,
					},
				}},
			},
			failureExpected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failFlag := test.setFailFlag
			repo := &utils.Repository{
				Params: utils.Params{
					Scan: utils.Scan{
						FailOnSecurityIssues: &failFlag,
					},
					Git: utils.Git{
						PullRequestSecretComments: false,
					},
				},
			}

			assert.Equal(t, test.failureExpected, toFailTaskStatus(repo, &test.issuesCollection))
		})
	}
}

func TestFilterJasResultsIfScanFailed(t *testing.T) {
	tests := []struct {
		name         string
		scanType     jasutils.JasScanType
		targetResult *results.TargetResults
		sourceResult *results.TargetResults
		hasFailure   bool
	}{
		{
			name:     "Applicability scanner failed - should remove applicability results",
			scanType: jasutils.Applicability,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
						{StatusCode: 0},
					},
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
						{StatusCode: 1},
					},
				},
			},
			hasFailure: true,
		},
		{
			name:     "Secrets scanner failed in target - should remove secrets vulnerabilities and violations",
			scanType: jasutils.Secrets,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
					JasViolations: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
					JasViolations: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
				},
			},
			hasFailure: true,
		},
		{
			name:     "IaC scanner failed in both source and target - should remove IaC vulnerabilities and violations",
			scanType: jasutils.IaC,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
					JasViolations: results.JasScanResults{
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
					JasViolations: results.JasScanResults{
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
				},
			},
			hasFailure: true,
		},
		{
			name:     "SAST scanner failed - should remove SAST vulnerabilities and violations",
			scanType: jasutils.Sast,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
					JasViolations: results.JasScanResults{
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
					JasViolations: results.JasScanResults{
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 1},
						},
					},
				},
			},
			hasFailure: true,
		},
		{
			name:     "All scanners succeed - should not remove any results",
			scanType: jasutils.Applicability,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
						{StatusCode: 0},
					},
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
					JasViolations: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
						{StatusCode: 0},
					},
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
					JasViolations: results.JasScanResults{
						SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						IacScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
						SastScanResults: []results.ScanResult[[]*sarif.Run]{
							{StatusCode: 0},
						},
					},
				},
			},
			hasFailure: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Call the function under test
			filterJasResultsIfScanFailed(test.targetResult, test.sourceResult, test.scanType)

			// Validate the results based on scan type and test case
			if !test.hasFailure {
				// For success cases, results should NOT be removed
				assert.NotNil(t, test.sourceResult.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets vulnerability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasViolations.SecretsScanResults, "Secrets violation scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasVulnerabilities.IacScanResults, "IaC vulnerability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasViolations.IacScanResults, "IaC violation scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasVulnerabilities.SastScanResults, "SAST vulnerability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasViolations.SastScanResults, "SAST violation scan results should NOT be removed when scan succeeds")
			} else {
				// For failure cases, results should be removed
				switch test.scanType {
				case jasutils.Applicability:
					assert.Nil(t, test.sourceResult.JasResults.ApplicabilityScanResults, "Applicability scan results should be removed when scan failed")
				case jasutils.Secrets:
					assert.Nil(t, test.sourceResult.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets vulnerability scan results should be removed when scan failed")
					assert.Nil(t, test.sourceResult.JasResults.JasViolations.SecretsScanResults, "Secrets violation scan results should be removed when scan failed")
				case jasutils.IaC:
					assert.Nil(t, test.sourceResult.JasResults.JasVulnerabilities.IacScanResults, "IaC vulnerability scan results should be removed when scan failed")
					assert.Nil(t, test.sourceResult.JasResults.JasViolations.IacScanResults, "IaC violation scan results should be removed when scan failed")
				case jasutils.Sast:
					assert.Nil(t, test.sourceResult.JasResults.JasVulnerabilities.SastScanResults, "SAST vulnerability scan results should be removed when scan failed")
					assert.Nil(t, test.sourceResult.JasResults.JasViolations.SastScanResults, "SAST violation scan results should be removed when scan failed")
				}
			}
		})
	}
}

func TestFilterOutScaResultsIfScanFailed(t *testing.T) {
	tests := []struct {
		name         string
		targetResult *results.TargetResults
		sourceResult *results.TargetResults
		hasFailure   bool
	}{
		{
			name: "SCA scan failed - should remove SCA results",
			targetResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					ScanStatusCode: -1,
					Sbom:           nil,
					Violations:     []services.Violation{{IssueId: "test-violation"}},
				},
			},
			sourceResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					ScanStatusCode: 0,
					Sbom:           nil,
					Violations:     []services.Violation{{IssueId: "source-violation"}},
				},
			},
			hasFailure: true,
		},
		{
			name: "SCA scan succeeded - should not remove SCA results",
			targetResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					ScanStatusCode: 0,
					Sbom:           nil,
					Violations:     []services.Violation{{IssueId: "target-violation"}},
				},
			},
			sourceResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					ScanStatusCode: 0,
					Sbom:           nil,
					Violations:     []services.Violation{{IssueId: "source-violation"}},
				},
			},
			hasFailure: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filterOutScaResultsIfScanFailed(test.targetResult, test.sourceResult)

			if test.hasFailure {
				assert.Nil(t, test.sourceResult.ScaResults.Sbom, "SBOM should be removed when SCA scan failed")
				assert.Nil(t, test.sourceResult.ScaResults.Violations, "Violations should be removed when SCA scan failed")
			} else {
				assert.Equal(t, []services.Violation{{IssueId: "source-violation"}}, test.sourceResult.ScaResults.Violations, "Violations should NOT be removed when SCA scan succeeds")
			}
		})
	}
}

func TestFilterOutFailedScansIfAllowPartialResultsEnabled(t *testing.T) {
	tests := []struct {
		name          string
		targetResults *results.SecurityCommandResults
		sourceResults *results.SecurityCommandResults
		hasFailure    bool
	}{
		{
			name: "All scans succeed - should not filter anything",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{
						ScanTarget: results.ScanTarget{Target: "test-target"},
						ScaResults: &results.ScaScanResults{
							ScanStatusCode: 0,
							Violations:     []services.Violation{{IssueId: "target-violation"}},
						},
						JasResults: &results.JasScansResults{
							ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
								{StatusCode: 0},
							},
							JasVulnerabilities: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
							JasViolations: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
						},
					},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{
						ScanTarget: results.ScanTarget{Target: "test-target"},
						ScaResults: &results.ScaScanResults{
							ScanStatusCode: 0,
							Violations:     []services.Violation{{IssueId: "source-violation"}},
						},
						JasResults: &results.JasScansResults{
							ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
								{StatusCode: 0},
							},
							JasVulnerabilities: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
							JasViolations: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
						},
					},
				},
			},
			hasFailure: false,
		},
		{
			name: "SCA and 2 JAS scanners failed - should filter SCA, Secrets, and IaC results",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{
						ScanTarget: results.ScanTarget{Target: "test-target"},
						ScaResults: &results.ScaScanResults{
							ScanStatusCode: -1,
							Violations:     []services.Violation{{IssueId: "target-violation"}},
						},
						JasResults: &results.JasScansResults{
							ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
								{StatusCode: 0},
							},
							JasVulnerabilities: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 1},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 1},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
							JasViolations: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 1},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 1},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
						},
					},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{
						ScanTarget: results.ScanTarget{Target: "test-target"},
						ScaResults: &results.ScaScanResults{
							ScanStatusCode: 0,
							Violations:     []services.Violation{{IssueId: "source-violation"}},
						},
						JasResults: &results.JasScansResults{
							ApplicabilityScanResults: []results.ScanResult[[]*sarif.Run]{
								{StatusCode: 0},
							},
							JasVulnerabilities: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
							JasViolations: results.JasScanResults{
								SecretsScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								IacScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
								SastScanResults: []results.ScanResult[[]*sarif.Run]{
									{StatusCode: 0},
								},
							},
						},
					},
				},
			},
			hasFailure: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := filterOutFailedScansIfAllowPartialResultsEnabled(test.targetResults, test.sourceResults, true)
			assert.NoError(t, err)

			sourceTarget := test.sourceResults.Targets[0]
			if test.hasFailure {
				assert.Nil(t, sourceTarget.ScaResults.Violations, "SCA violations should be removed when SCA scan failed")
				assert.Nil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should be removed when Secrets scan failed")
				assert.Nil(t, sourceTarget.JasResults.JasViolations.SecretsScanResults, "Secrets violation results should be removed when Secrets scan failed")
				assert.Nil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should be removed when IaC scan failed")
				assert.Nil(t, sourceTarget.JasResults.JasViolations.IacScanResults, "IaC violation results should be removed when IaC scan failed")
				assert.NotNil(t, sourceTarget.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be removed when Applicability scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SastScanResults, "SAST scan results should NOT be removed when SAST scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasViolations.SastScanResults, "SAST violation results should NOT be removed when SAST scan succeeds")
			} else {
				assert.NotNil(t, sourceTarget.ScaResults.Violations, "SCA violations should NOT be removed when SCA scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should NOT be removed when Secrets scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasViolations.SecretsScanResults, "Secrets violation results should NOT be removed when Secrets scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should NOT be removed when IaC scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasViolations.IacScanResults, "IaC violation results should NOT be removed when IaC scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be removed when Applicability scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SastScanResults, "SAST scan results should NOT be removed when SAST scan succeeds")
				assert.NotNil(t, sourceTarget.JasResults.JasViolations.SastScanResults, "SAST violation results should NOT be removed when SAST scan succeeds")
			}
		})
	}
}

func preparePullRequestTest(t *testing.T, projectName string) (utils.RepoAggregator, vcsclient.VcsClient, func()) {
	params, restoreEnv := utils.VerifyEnv(t)

	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(&params)
	assert.NoError(t, err)

	// Create mock GitLab server
	owner := "jfrog"
	gitServerParams := GitServerParams{
		RepoOwner: owner,
		RepoName:  projectName,
		prDetails: vcsclient.PullRequestInfo{ID: int64(1),
			Source: vcsclient.BranchInfo{Name: testSourceBranchName, Repository: projectName, Owner: owner},
			Target: vcsclient.BranchInfo{Name: testTargetBranchName, Repository: projectName, Owner: owner},
		},
	}
	server := httptest.NewServer(createGitLabHandler(t, gitServerParams))

	testDir, cleanUp := utils.CopyTestdataProjectsToTemp(t, "scanpullrequest")
	configAggregator, client := prepareConfigAndClient(t, xrayVersion, xscVersion, server, params, gitServerParams)

	// Renames test git folder to .git
	currentDir := filepath.Join(testDir, projectName)
	restoreDir, err := utils.Chdir(currentDir)
	assert.NoError(t, err)

	return configAggregator, client, func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(currentDir))
		cleanUp()
		server.Close()
		restoreEnv()
	}
}

type GitServerParams struct {
	RepoOwner string
	RepoName  string
	prDetails vcsclient.PullRequestInfo
}

// Create HTTP handler to mock GitLab server
func createGitLabHandler(t *testing.T, params GitServerParams) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		repoInfo := params.RepoOwner + "%2F" + params.RepoName
		switch {
		// Return 200 on ping
		case r.RequestURI == "/api/v4/":
			w.WriteHeader(http.StatusOK)
		// Mimic get pull request by ID
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/%d", repoInfo, params.prDetails.ID):
			w.WriteHeader(http.StatusOK)
			// expectedResponse, err := os.ReadFile(filepath.Join("..", "expectedPullRequestDetailsResponse.json"))
			// assert.NoError(t, err)
			_, err := w.Write([]byte(fmt.Sprintf(`{ "id": %d, "iid": 133, "project_id": 15513260, "title": "Dummy pull request", "description": "this is pr description", "state": "opened", "target_branch": "%s", "source_branch": "%s", "author": {"username": "testuser"}}`, params.prDetails.ID, params.prDetails.Target.Name, params.prDetails.Source.Name)))
			assert.NoError(t, err)
		// Mimic download specific branch to scan
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/repository/archive.tar.gz?sha=%s", repoInfo, params.prDetails.Source.Name):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", params.RepoName, "sourceBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
		// Download repository mock
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/repository/archive.tar.gz?sha=%s", repoInfo, params.prDetails.Target.Name):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", params.RepoName, "targetBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
			return
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/notes", repoInfo) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		// Return 200 when using the REST that creates the comment
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/notes", repoInfo) && r.Method == http.MethodPost:
			if params.RepoName == "clean-test-proj" {
				// clean-test-proj should not include any vulnerabilities so assertion is not needed.
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("{}"))
				assert.NoError(t, err)
				return
			}
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			assert.NoError(t, err)
			assert.NotEmpty(t, buf.String())

			var expectedResponse []byte
			if strings.Contains(params.RepoName, "multi-dir") {
				expectedResponse = outputwriter.GetJsonBodyOutputFromFile(t, filepath.Join("..", "expected_response_multi_dir.md"))
			} else {
				expectedResponse = outputwriter.GetJsonBodyOutputFromFile(t, filepath.Join("..", "expected_response.md"))
			}
			assert.NoError(t, err)
			assert.JSONEq(t, string(expectedResponse), buf.String())

			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("{}"))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s", repoInfo):
			jsonResponse := `{"id": 3,"visibility": "private","ssh_url_to_repo": "git@example.com:diaspora/diaspora-project-site.git","http_url_to_repo": "https://example.com/diaspora/diaspora-project-site.git"}`
			_, err := w.Write([]byte(jsonResponse))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/%s/merge_requests/133/discussions", repoInfo):
			discussions, err := os.ReadFile(filepath.Join("..", "list_merge_request_discussion_items.json"))
			assert.NoError(t, err)
			_, err = w.Write(discussions)
			assert.NoError(t, err)
		}
	}
}
