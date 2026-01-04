package scanpullrequest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	services2 "github.com/jfrog/jfrog-client-go/xsc/services"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	securityutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/frogbot/v2/testdata"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
)

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=../testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient

const (
	testSourceBranchName = "pr"
	testTargetBranchName = "master"
)

var emptyConfigProfile = services2.ConfigProfile{
	ProfileName:   "test-profile",
	GeneralConfig: services2.GeneralConfig{},
	FrogbotConfig: services2.FrogbotConfig{
		BranchNameTemplate:    "",
		PrTitleTemplate:       "",
		CommitMessageTemplate: "",
	},
	Modules: []services2.Module{
		{
			ModuleId:     0,
			ModuleName:   "test-module",
			PathFromRoot: ".",
		},
	},
}

func CreateMockVcsClient(t *testing.T) *testdata.MockVcsClient {
	return testdata.NewMockVcsClient(gomock.NewController(t))
}

func TestScanResultsToIssuesCollection(t *testing.T) {
	auditResults := &results.SecurityCommandResults{ResultsMetaData: results.ResultsMetaData{EntitledForJas: true, ResultContext: results.ResultContext{IncludeVulnerabilities: true}}, Targets: []*results.TargetResults{{
		ResultsStatus: results.ResultsStatus{
			ScaScanStatusCode:            securityutils.NewIntPtr(0),
			ContextualAnalysisStatusCode: securityutils.NewIntPtr(0),
			IacScanStatusCode:            securityutils.NewIntPtr(0),
			SecretsScanStatusCode:        securityutils.NewIntPtr(0),
			SastScanStatusCode:           securityutils.NewIntPtr(0),
		},
		ScanTarget: results.ScanTarget{Target: "dummy"},
		ScaResults: &results.ScaScanResults{
			DeprecatedXrayResults: []services.ScanResponse{{
				Vulnerabilities: []services.Vulnerability{
					{Cves: []services.Cve{{Id: "CVE-2022-2122"}}, Severity: "High", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}},
					{Cves: []services.Cve{{Id: "CVE-2023-3122"}}, Severity: "Low", Components: map[string]services.Component{"Dep-2": {FixedVersions: []string{"1.2.2"}}}},
				},
				Licenses: []services.License{{Key: "Apache-2.0", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}}},
			}},
		},
		JasResults: &results.JasScansResults{
			ApplicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResultAndRuleInformation(
					sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2022-2122", ""),
					"rule-msg", "rule-markdown", []string{"applicability"}, []string{"applicable"},
				),
				sarifutils.CreateRunWithDummyResultAndRuleInformation(
					sarifutils.CreateDummyResult("result-markdown", "result-msg", "applic_CVE-2023-3122", ""),
					"rule-msg", "rule-markdown", []string{"applicability"}, []string{"not_applicable"},
				),
			},
			JasVulnerabilities: results.JasScanResults{
				IacScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
						),
					),
				},
				SecretsScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("index.js", 5, 6, 7, 8, "access token exposed"),
						),
					),
				},
				SastScanResults: []*sarif.Run{
					sarifutils.CreateRunWithDummyResults(
						sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
							sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
						),
					),
				},
			},
		},
	}}}
	expectedOutput := &issues.ScansIssuesCollection{
		ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				Applicable:    "Applicable",
				FixedVersions: []string{"1.2.3"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 31},
					ImpactedDependencyName: "Dep-1",
				},
				Cves: []formats.CveRow{{Id: "CVE-2022-2122", Applicability: &formats.Applicability{Status: "Applicable", ScannerDescription: "rule-msg", Evidence: []formats.Evidence{{Reason: "result-msg", Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			},
			{
				Applicable:    "Not Applicable",
				FixedVersions: []string{"1.2.2"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 3},
					ImpactedDependencyName: "Dep-2",
				},
				Cves: []formats.CveRow{{Id: "CVE-2023-3122", Applicability: &formats.Applicability{Status: "Not Applicable", ScannerDescription: "rule-msg"}}},
			},
		},
		IacVulnerabilities: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 31,
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
					SeverityNumValue: 31,
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
					SeverityNumValue: 31,
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
	}

	issuesRows, err := scanResultsToIssuesCollection(auditResults)

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
		testName    string
		projectName string
	}{
		{
			testName:    "ScanPullRequest",
			projectName: "test-proj",
		},
		{
			testName:    "ScanPullRequestNoFail",
			projectName: "test-proj",
		},
		{
			testName:    "ScanPullRequestSubdir",
			projectName: "test-proj-subdir",
		},
		{
			testName:    "ScanPullRequestNoIssues",
			projectName: "clean-test-proj",
		},
		{
			testName:    "ScanPullRequestMultiWorkDir",
			projectName: "multi-dir-test-proj",
		},
		{
			testName:    "ScanPullRequestMultiWorkDirNoFail",
			projectName: "multi-dir-test-proj",
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			testScanPullRequest(t, test.projectName)
		})
	}
}

func testScanPullRequest(t *testing.T, projectName string) {
	config, client, cleanUp := preparePullRequestTest(t, projectName)
	defer cleanUp()

	// Run "frogbot scan pull request"
	var scanPullRequest ScanPullRequestCmd
	err := scanPullRequest.Run(config, client)
	assert.NoError(t, err)

	// Check env sanitize
	err = utils.SanitizeEnv()
	assert.NoError(t, err)
	utils.AssertSanitizedEnv(t)
}

func prepareConfigAndClient(t *testing.T, xrayVersion, xscVersion string, server *httptest.Server, serverParams coreconfig.ServerDetails, gitServerParams GitServerParams) (utils.Repository, vcsclient.VcsClient) {
	gitTestParams := &utils.Git{
		GitProvider: vcsutils.GitHub,
		RepoOwner:   gitServerParams.RepoOwner,
		RepoName:    gitServerParams.RepoName,
		VcsInfo: vcsclient.VcsInfo{
			Token:       "123456",
			APIEndpoint: server.URL,
		},
		PullRequestDetails: gitServerParams.prDetails,
	}
	utils.SetEnvAndAssert(t, map[string]string{utils.GitPullRequestIDEnv: fmt.Sprintf("%d", gitServerParams.prDetails.ID)})

	client, err := vcsclient.NewClientBuilder(vcsutils.GitLab).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	repository, err := utils.BuildRepositoryFromEnv(xrayVersion, xscVersion, client, gitTestParams, &serverParams, utils.ScanPullRequest)
	assert.NoError(t, err)

	// We must set a non-nil config profile to avoid panic
	repository.ConfigProfile = &emptyConfigProfile

	return repository, client
}

func TestDeleteExistingPullRequestComments(t *testing.T) {
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

func TestDeleteExistingPullRequestReviewComments(t *testing.T) {
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

			issuesCollection, _, err := auditPullRequestAndReport(&repoConfig, client)
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
			name:        "no violations with fail_pr",
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
			name:        "fail_pr in licenses violation",
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
			assert.Equal(t, test.failureExpected, test.issuesCollection.IsFailPrRuleApplied())
		})
	}
}

func TestFilterJasResultsIfScanFailed(t *testing.T) {
	tests := []struct {
		name         string
		cmdStep      results.SecurityCommandStep
		targetResult *results.TargetResults
		sourceResult *results.TargetResults
		hasFailure   bool
	}{
		{
			name:    "Applicability scanner failed - should remove applicability results",
			cmdStep: results.CmdStepContextualAnalysis,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []*sarif.Run{},
				},
				ResultsStatus: results.ResultsStatus{
					ContextualAnalysisStatusCode: intPtr(0),
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []*sarif.Run{},
				},
				ResultsStatus: results.ResultsStatus{
					ContextualAnalysisStatusCode: intPtr(1),
				},
			},
			hasFailure: true,
		},
		{
			name:    "Secrets scanner failed in target - should remove secrets vulnerabilities",
			cmdStep: results.CmdStepSecrets,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					SecretsScanStatusCode: intPtr(1),
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					SecretsScanStatusCode: intPtr(0),
				},
			},
			hasFailure: true,
		},
		{
			name:    "IaC scanner failed in both source and target - should remove IaC vulnerabilities",
			cmdStep: results.CmdStepIaC,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						IacScanResults: []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					IacScanStatusCode: intPtr(1),
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						IacScanResults: []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					IacScanStatusCode: intPtr(1),
				},
			},
			hasFailure: true,
		},
		{
			name:    "SAST scanner failed - should remove SAST vulnerabilities",
			cmdStep: results.CmdStepSast,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SastScanResults: []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					SastScanStatusCode: intPtr(0),
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SastScanResults: []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					SastScanStatusCode: intPtr(1),
				},
			},
			hasFailure: true,
		},
		{
			name:    "All scanners succeed - should not remove any results",
			cmdStep: results.CmdStepContextualAnalysis,
			targetResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []*sarif.Run{},
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []*sarif.Run{},
						IacScanResults:     []*sarif.Run{},
						SastScanResults:    []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					ContextualAnalysisStatusCode: intPtr(0),
					SecretsScanStatusCode:        intPtr(0),
					IacScanStatusCode:            intPtr(0),
					SastScanStatusCode:           intPtr(0),
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					ApplicabilityScanResults: []*sarif.Run{},
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []*sarif.Run{},
						IacScanResults:     []*sarif.Run{},
						SastScanResults:    []*sarif.Run{},
					},
				},
				ResultsStatus: results.ResultsStatus{
					ContextualAnalysisStatusCode: intPtr(0),
					SecretsScanStatusCode:        intPtr(0),
					IacScanStatusCode:            intPtr(0),
					SastScanStatusCode:           intPtr(0),
				},
			},
			hasFailure: false,
		},
		{
			name:    "JasResults is nil - should not panic",
			cmdStep: results.CmdStepContextualAnalysis,
			targetResult: &results.TargetResults{
				JasResults: nil,
				ResultsStatus: results.ResultsStatus{
					ContextualAnalysisStatusCode: intPtr(1),
				},
			},
			sourceResult: &results.TargetResults{
				JasResults: nil,
				ResultsStatus: results.ResultsStatus{
					ContextualAnalysisStatusCode: intPtr(0),
				},
			},
			hasFailure: true,
		},
		{
			name:         "Target is nil, source scan failed - should remove results",
			cmdStep:      results.CmdStepSecrets,
			targetResult: nil,
			sourceResult: &results.TargetResults{
				JasResults: &results.JasScansResults{
					JasVulnerabilities: results.JasScanResults{
						SecretsScanResults: []*sarif.Run{{}},
					},
				},
				ResultsStatus: results.ResultsStatus{
					SecretsScanStatusCode: intPtr(1),
				},
			},
			hasFailure: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filterJasResultsIfScanFailed(test.targetResult, test.sourceResult, test.cmdStep)

			if !test.hasFailure {
				assert.NotNil(t, test.sourceResult.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets vulnerability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasVulnerabilities.IacScanResults, "IaC vulnerability scan results should NOT be removed when scan succeeds")
				assert.NotNil(t, test.sourceResult.JasResults.JasVulnerabilities.SastScanResults, "SAST vulnerability scan results should NOT be removed when scan succeeds")
			} else if test.sourceResult.JasResults != nil {
				// If JasResults is nil, and we got to this point without panicking - it means the func handles this case correctly
				switch test.cmdStep {
				case results.CmdStepContextualAnalysis:
					assert.Nil(t, test.sourceResult.JasResults.ApplicabilityScanResults, "Applicability scan results should be removed when scan failed")
				case results.CmdStepSecrets:
					assert.Nil(t, test.sourceResult.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets vulnerability scan results should be removed when scan failed")
				case results.CmdStepIaC:
					assert.Nil(t, test.sourceResult.JasResults.JasVulnerabilities.IacScanResults, "IaC vulnerability scan results should be removed when scan failed")
				case results.CmdStepSast:
					assert.Nil(t, test.sourceResult.JasResults.JasVulnerabilities.SastScanResults, "SAST vulnerability scan results should be removed when scan failed")
				}
			}
		})
	}
}

func TestFilterScaResultsIfScanFailed(t *testing.T) {
	tests := []struct {
		name         string
		targetResult *results.TargetResults
		sourceResult *results.TargetResults
		hasFailure   bool
	}{
		{
			name: "SCA scan failed in target - should remove SCA results",
			targetResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(1),
				},
			},
			sourceResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			hasFailure: true,
		},
		{
			name: "SCA scan failed in source - should remove SCA results",
			targetResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			sourceResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(1),
				},
			},
			hasFailure: true,
		},
		{
			name: "SCA scan succeeded - should not remove SCA results",
			targetResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			sourceResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			hasFailure: false,
		},
		{
			name:         "Target is nil, source scan failed - should remove SCA results",
			targetResult: nil,
			sourceResult: &results.TargetResults{
				ScaResults: &results.ScaScanResults{
					Sbom: &cyclonedx.BOM{},
				},
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(1),
				},
			},
			hasFailure: true,
		},
		{
			name: "ScaResults is nil - should not panic",
			targetResult: &results.TargetResults{
				ScaResults: nil,
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(1),
				},
			},
			sourceResult: &results.TargetResults{
				ScaResults: nil,
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			hasFailure: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filterScaResultsIfScanFailed(test.targetResult, test.sourceResult)

			// If ScaResults is nil, and we got to this point without panicking - it means the func handles this case correctly
			if test.hasFailure {
				if test.sourceResult.ScaResults != nil {
					assert.Nil(t, test.sourceResult.ScaResults.Sbom, "SBOM should be removed when SCA scan failed")
				}
			} else {
				if test.sourceResult.ScaResults != nil {
					assert.NotNil(t, test.sourceResult.ScaResults.Sbom, "SBOM should NOT be removed when SCA scan succeeded")
				}
			}
		})
	}
}

func TestFilterFailedResultsIfScannersFailuresAreAllowed(t *testing.T) {
	tests := []struct {
		name                    string
		targetResults           *results.SecurityCommandResults
		sourceResults           *results.SecurityCommandResults
		failUponAnyScannerError bool
		validate                func(t *testing.T, sourceResults *results.SecurityCommandResults)
	}{
		{
			name:                    "FailUponAnyScannerError is true - should not filter anything",
			targetResults:           createSecurityCommandResultsForTest("test", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
			sourceResults:           createSecurityCommandResultsForTest("test", "", true, true, true, true, true, false, 1, 1, 1, 1, 1, 0),
			failUponAnyScannerError: true,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				sourceTarget := sourceResults.Targets[0]
				assert.NotNil(t, sourceTarget.ScaResults.Sbom, "SCA SBOM should NOT be filtered when failUponAnyScannerError is true")
				assert.NotNil(t, sourceTarget.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be filtered when failUponAnyScannerError is true")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should NOT be filtered when failUponAnyScannerError is true")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should NOT be filtered when failUponAnyScannerError is true")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SastScanResults, "SAST scan results should NOT be filtered when failUponAnyScannerError is true")
			},
		},
		{
			name:                    "targetResults is nil - should not filter anything",
			targetResults:           nil,
			sourceResults:           createSecurityCommandResultsForTest("test", "", true, true, true, true, true, false, 1, 1, 1, 1, 1, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				sourceTarget := sourceResults.Targets[0]
				assert.NotNil(t, sourceTarget.ScaResults.Sbom, "SCA SBOM should NOT be filtered when targetResults is nil")
				assert.NotNil(t, sourceTarget.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be filtered when targetResults is nil")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should NOT be filtered when targetResults is nil")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should NOT be filtered when targetResults is nil")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SastScanResults, "SAST scan results should NOT be filtered when targetResults is nil")
			},
		},
		{
			name:                    "All scans succeed - should not filter anything",
			targetResults:           createSecurityCommandResultsForTest("test-target", "test-name", true, true, true, true, true, false, 0, 0, 0, 0, 0, 0),
			sourceResults:           createSecurityCommandResultsForTest("test-target", "test-name", true, true, true, true, true, false, 0, 0, 0, 0, 0, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				sourceTarget := sourceResults.Targets[0]
				assert.NotNil(t, sourceTarget.ScaResults.Sbom, "SCA SBOM should NOT be removed when all scans succeed")
				assert.NotNil(t, sourceTarget.JasResults.ApplicabilityScanResults, "Applicability scan results should NOT be removed")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should NOT be removed")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should NOT be removed")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SastScanResults, "SAST scan results should NOT be removed")
			},
		},
		{
			name:                    "SCA and Secrets scanners failed in target - should filter SCA and Secrets results",
			targetResults:           createSecurityCommandResultsForTest("test-target", "", false, false, true, false, false, false, 1, 0, 1, 0, 0, 0),
			sourceResults:           createSecurityCommandResultsForTest("test-target", "", true, false, true, true, true, false, 0, 0, 0, 0, 0, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				sourceTarget := sourceResults.Targets[0]
				assert.Nil(t, sourceTarget.ScaResults.Sbom, "SCA SBOM should be removed when SCA scan failed")
				assert.Nil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should be removed when Secrets scan failed")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should NOT be removed")
				assert.NotNil(t, sourceTarget.JasResults.JasVulnerabilities.SastScanResults, "SAST scan results should NOT be removed")
			},
		},
		{
			name:                    "New target in source (unmatched) with failures - should filter based on source failures only",
			targetResults:           createSecurityCommandResultsForTest("old-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
			sourceResults:           createSecurityCommandResultsForTest("new-target", "", true, false, true, false, false, false, 1, 0, 1, 0, 0, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				sourceTarget := sourceResults.Targets[0]
				assert.Nil(t, sourceTarget.ScaResults.Sbom, "SCA SBOM should be removed when source SCA scan failed")
				assert.Nil(t, sourceTarget.JasResults.JasVulnerabilities.SecretsScanResults, "Secrets scan results should be removed when source Secrets scan failed")
			},
		},
		{
			name:                    "Target matched by name (location changed)",
			targetResults:           createSecurityCommandResultsForTest("old-location", "same-name", false, false, false, true, false, false, 0, 0, 0, 1, 0, 0),
			sourceResults:           createSecurityCommandResultsForTest("new-location", "same-name", false, false, false, true, false, false, 0, 0, 0, 0, 0, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				sourceTarget := sourceResults.Targets[0]
				assert.Nil(t, sourceTarget.JasResults.JasVulnerabilities.IacScanResults, "IaC scan results should be removed when target IaC scan failed (matched by name)")
			},
		},
		{
			name: "ViolationsStatusCode is nil - ensure we dont have violations when func is done",
			targetResults: func() *results.SecurityCommandResults {
				result := createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0)
				result.ViolationsStatusCode = nil
				return result
			}(),
			sourceResults: func() *results.SecurityCommandResults {
				result := createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 0)
				result.ViolationsStatusCode = nil
				return result
			}(),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				assert.Nil(t, sourceResults.Violations, "Violations should be nil when ViolationsStatusCode is nil")
			},
		},
		{
			name:                    "Violations scan failed - should remove all violations",
			targetResults:           createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 1),
			sourceResults:           createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				assert.Nil(t, sourceResults.Violations, "All violations should be removed when violations scan failed")
			},
		},
		{
			name:                    "Specific scanner failed but violations scan succeeded - should filter only that scanner's violations",
			targetResults:           createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 1, 0, 0, 0, 0, 0),
			sourceResults:           createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 0),
			failUponAnyScannerError: false,
			validate: func(t *testing.T, sourceResults *results.SecurityCommandResults) {
				assert.Nil(t, sourceResults.Violations.Sca, "SCA violations should be removed when SCA scan failed")
				assert.NotNil(t, sourceResults.Violations.Secrets, "Secrets violations should NOT be removed")
				assert.NotNil(t, sourceResults.Violations.Iac, "IaC violations should NOT be removed")
				assert.NotNil(t, sourceResults.Violations.Sast, "SAST violations should NOT be removed")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filterFailedResultsIfScannersFailuresAreAllowed(test.targetResults, test.sourceResults, test.failUponAnyScannerError, "", "")
			test.validate(t, test.sourceResults)
		})
	}
}

func TestBuildTargetMappings(t *testing.T) {
	tests := []struct {
		name                    string
		targetResults           *results.SecurityCommandResults
		sourceResults           *results.SecurityCommandResults
		sourceWdPrefix          string
		targetWdPrefix          string
		expectedMatchedLocation int
		expectedMatchedName     int
		expectedUnmatched       int
		extraValidation         func(t *testing.T, matchedByLocation, matchedByName map[string]*targetPair, unmatchedSource []*results.TargetResults)
	}{
		{
			name: "Match by location - same number of targets",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1", Name: "name1"}},
					{ScanTarget: results.ScanTarget{Target: "target2", Name: "name2"}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1", Name: "name1"}},
					{ScanTarget: results.ScanTarget{Target: "target2", Name: "name2"}},
				},
			},
			sourceWdPrefix:          "",
			targetWdPrefix:          "",
			expectedMatchedLocation: 2,
			expectedMatchedName:     0,
			expectedUnmatched:       0,
			extraValidation: func(t *testing.T, matchedByLocation, matchedByName map[string]*targetPair, unmatchedSource []*results.TargetResults) {
				assert.NotNil(t, matchedByLocation["target1"], "target1 should be matched")
				assert.NotNil(t, matchedByLocation["target2"], "target2 should be matched")
			},
		},
		{
			name: "Match by name when location changed",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "old-location", Name: "same-name"}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "new-location", Name: "same-name"}},
				},
			},
			sourceWdPrefix:          "",
			targetWdPrefix:          "",
			expectedMatchedLocation: 0,
			expectedMatchedName:     1,
			expectedUnmatched:       0,
			extraValidation: func(t *testing.T, matchedByLocation, matchedByName map[string]*targetPair, unmatchedSource []*results.TargetResults) {
				assert.NotNil(t, matchedByName["same-name"], "same-name should be matched")
			},
		},
		{
			name: "New target in source (unmatched)",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1"}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1"}},
					{ScanTarget: results.ScanTarget{Target: "new-target"}},
				},
			},
			sourceWdPrefix:          "",
			targetWdPrefix:          "",
			expectedMatchedLocation: 1,
			expectedMatchedName:     0,
			expectedUnmatched:       1,
			extraValidation: func(t *testing.T, matchedByLocation, matchedByName map[string]*targetPair, unmatchedSource []*results.TargetResults) {
				assert.Equal(t, "new-target", unmatchedSource[0].ScanTarget.Target, "Unmatched target should be new-target")
			},
		},
		{
			name: "Target removed in source (target-only, should be ignored)",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1"}},
					{ScanTarget: results.ScanTarget{Target: "removed-target"}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1"}},
				},
			},
			sourceWdPrefix:          "",
			targetWdPrefix:          "",
			expectedMatchedLocation: 1,
			expectedMatchedName:     0,
			expectedUnmatched:       0,
		},
		{
			name: "Empty target field - should not match by location",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "", Name: "name1"}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "", Name: "name1"}},
				},
			},
			sourceWdPrefix:          "",
			targetWdPrefix:          "",
			expectedMatchedLocation: 0,
			expectedMatchedName:     1,
			expectedUnmatched:       0,
		},
		{
			name: "Empty name field - should not match by name",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1", Name: ""}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: "target1", Name: ""}},
				},
			},
			sourceWdPrefix:          "",
			targetWdPrefix:          "",
			expectedMatchedLocation: 1,
			expectedMatchedName:     0,
			expectedUnmatched:       0,
		},
		{
			name: "Match by location with different working directory prefixes",
			targetResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: filepath.Join("tmp", "target-wd", "project1", "src"), Name: "project1"}},
					{ScanTarget: results.ScanTarget{Target: filepath.Join("tmp", "target-wd", "project2", "lib"), Name: "project2"}},
				},
			},
			sourceResults: &results.SecurityCommandResults{
				Targets: []*results.TargetResults{
					{ScanTarget: results.ScanTarget{Target: filepath.Join("tmp", "source-wd", "project1", "src"), Name: "project1"}},
					{ScanTarget: results.ScanTarget{Target: filepath.Join("tmp", "source-wd", "project2", "lib"), Name: "project2"}},
				},
			},
			sourceWdPrefix:          filepath.Join("tmp", "source-wd"),
			targetWdPrefix:          filepath.Join("tmp", "target-wd"),
			expectedMatchedLocation: 2,
			expectedMatchedName:     0,
			expectedUnmatched:       0,
			extraValidation: func(t *testing.T, matchedByLocation, matchedByName map[string]*targetPair, unmatchedSource []*results.TargetResults) {
				sourceTarget1 := filepath.Join("tmp", "source-wd", "project1", "src")
				sourceTarget2 := filepath.Join("tmp", "source-wd", "project2", "lib")
				assert.NotNil(t, matchedByLocation[sourceTarget1], "project1/src should be matched after trimming")
				assert.NotNil(t, matchedByLocation[sourceTarget2], "project2/lib should be matched after trimming")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedByLocation, matchedByName, unmatchedSource := buildTargetMappings(test.targetResults, test.sourceResults, test.sourceWdPrefix, test.targetWdPrefix)
			assert.Len(t, matchedByLocation, test.expectedMatchedLocation, "Matched by location count")
			assert.Len(t, matchedByName, test.expectedMatchedName, "Matched by name count")
			assert.Len(t, unmatchedSource, test.expectedUnmatched, "Unmatched source count")
			if test.extraValidation != nil {
				test.extraValidation(t, matchedByLocation, matchedByName, unmatchedSource)
			}
		})
	}
}

func TestFilterViolationsResults(t *testing.T) {
	tests := []struct {
		name                      string
		sourceResults             *results.SecurityCommandResults
		targetResults             *results.SecurityCommandResults
		shouldRemoveSca           bool
		shouldRemoveSecrets       bool
		shouldRemoveIac           bool
		shouldRemoveSast          bool
		shouldRemoveAllViolations bool
	}{
		{
			name:                      "Violations scan failed in source - should remove all violations",
			sourceResults:             createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 1),
			targetResults:             createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
			shouldRemoveAllViolations: true,
		},
		{
			name:                      "Violations scan failed in target - should remove all violations",
			sourceResults:             createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 0),
			targetResults:             createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 1),
			shouldRemoveAllViolations: true,
		},
		{
			name:            "Violations scan succeeded, SCA scan failed in source - should remove only SCA violations",
			sourceResults:   createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 1, 0, 0, 0, 0, 0),
			targetResults:   createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
			shouldRemoveSca: true,
		},
		{
			name:                "Violations scan succeeded, Secrets scan failed in target - should remove only Secrets violations",
			sourceResults:       createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 0),
			targetResults:       createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 1, 0, 0, 0),
			shouldRemoveSecrets: true,
		},
		{
			name:            "Violations scan succeeded, IaC scan failed in both - should remove only IaC violations",
			sourceResults:   createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 1, 0, 0),
			targetResults:   createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 1, 0, 0),
			shouldRemoveIac: true,
		},
		{
			name:             "Violations scan succeeded, SAST scan failed in source - should remove only SAST violations",
			sourceResults:    createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 1, 0),
			targetResults:    createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
			shouldRemoveSast: true,
		},
		{
			name:                "Violations scan succeeded, multiple scanners failed - should remove multiple violations",
			sourceResults:       createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 1, 0, 0, 0, 0, 0),
			targetResults:       createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 1, 0, 0, 0),
			shouldRemoveSca:     true,
			shouldRemoveSecrets: true,
		},
		{
			name:          "Violations scan succeeded, all scans succeeded - should not remove any violations",
			sourceResults: createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, true, 0, 0, 0, 0, 0, 0),
			targetResults: createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
		},
		{
			name: "Violations is nil - should not panic",
			sourceResults: func() *results.SecurityCommandResults {
				result := createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0)
				result.Violations = nil
				return result
			}(),
			targetResults: createSecurityCommandResultsForTest("test-target", "", false, false, false, false, false, false, 0, 0, 0, 0, 0, 0),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filterViolationsResults(test.sourceResults, test.targetResults)

			if test.shouldRemoveAllViolations {
				assert.Nil(t, test.sourceResults.Violations, "All violations should be removed when violations scan failed")
			} else {
				if test.sourceResults.Violations == nil {
					// This avoids panic in the test where Violations is nil to begin with. If we get here, it means the func handled this case correctly.
					return
				}

				if test.shouldRemoveSca {
					assert.Nil(t, test.sourceResults.Violations.Sca, "SCA violations should be removed")
				} else {
					assert.NotNil(t, test.sourceResults.Violations.Sca, "SCA violations should NOT be removed")
				}

				if test.shouldRemoveSecrets {
					assert.Nil(t, test.sourceResults.Violations.Secrets, "Secrets violations should be removed")
				} else {
					assert.NotNil(t, test.sourceResults.Violations.Secrets, "Secrets violations should NOT be removed")
				}

				if test.shouldRemoveIac {
					assert.Nil(t, test.sourceResults.Violations.Iac, "IaC violations should be removed")
				} else {
					assert.NotNil(t, test.sourceResults.Violations.Iac, "IaC violations should NOT be removed")
				}

				if test.shouldRemoveSast {
					assert.Nil(t, test.sourceResults.Violations.Sast, "SAST violations should be removed")
				} else {
					assert.NotNil(t, test.sourceResults.Violations.Sast, "SAST violations should NOT be removed")
				}
			}
		})
	}
}

func TestIsScanFailedInSourceOrTarget(t *testing.T) {
	tests := []struct {
		name         string
		sourceResult *results.TargetResults
		targetResult *results.TargetResults
		step         results.SecurityCommandStep
		expected     bool
	}{
		{
			name: "Source scan failed - should return true",
			sourceResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(1),
				},
			},
			targetResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			step:     results.CmdStepSca,
			expected: true,
		},
		{
			name: "Target scan failed - should return true",
			sourceResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			targetResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(1),
				},
			},
			step:     results.CmdStepSca,
			expected: true,
		},
		{
			name: "Both scans succeeded - should return false",
			sourceResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			targetResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					ScaScanStatusCode: intPtr(0),
				},
			},
			step:     results.CmdStepSca,
			expected: false,
		},
		{
			name:         "Source is nil, target scan failed - should return true",
			sourceResult: nil,
			targetResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					SecretsScanStatusCode: intPtr(1),
				},
			},
			step:     results.CmdStepSecrets,
			expected: true,
		},
		{
			name: "Target is nil, source scan failed - should return true",
			sourceResult: &results.TargetResults{
				ResultsStatus: results.ResultsStatus{
					IacScanStatusCode: intPtr(1),
				},
			},
			targetResult: nil,
			step:         results.CmdStepIaC,
			expected:     true,
		},
		{
			name:         "Both are nil - should return false",
			sourceResult: nil,
			targetResult: nil,
			step:         results.CmdStepSast,
			expected:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isScanFailedInSourceOrTarget(test.sourceResult, test.targetResult, test.step)
			assert.Equal(t, test.expected, result)
		})
	}
}

func preparePullRequestTest(t *testing.T, projectName string) (utils.Repository, vcsclient.VcsClient, func()) {
	params, restoreEnv := utils.VerifyEnv(t)

	// Set test-specific environment variables
	envVars := map[string]string{}

	if len(envVars) > 0 {
		utils.SetEnvAndAssert(t, envVars)
	}

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
	config, client := prepareConfigAndClient(t, xrayVersion, xscVersion, server, params, gitServerParams)

	// Renames test git folder to .git
	currentDir := filepath.Join(testDir, projectName)
	restoreDir, err := utils.Chdir(currentDir)
	assert.NoError(t, err)

	return config, client, func() {
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
			_, err := fmt.Fprintf(w, `{ "id": %d, "iid": 133, "project_id": 15513260, "title": "Dummy pull request", "description": "this is pr description", "state": "opened", "target_branch": "%s", "source_branch": "%s", "author": {"username": "testuser"}}`, params.prDetails.ID, params.prDetails.Target.Name, params.prDetails.Source.Name)
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

func intPtr(i int) *int {
	return &i
}

func createSecurityCommandResultsForTest(targetLocation string, targetName string, withScaResults bool, withCaResults bool, withSecretsResult bool, withIacResults bool, withSastResults bool, withViolations bool, scaStatusCode int, caStatusCode int, secretsStatusCode int, iacStatusCode int, sastStatusCode int, violationsStatusCode int) *results.SecurityCommandResults {
	targetResults := &results.TargetResults{
		ScanTarget: results.ScanTarget{Target: targetLocation, Name: targetName},
	}

	if withScaResults {
		targetResults.ScaResults = &results.ScaScanResults{
			Sbom: &cyclonedx.BOM{},
		}
	}

	if withCaResults || withSecretsResult || withIacResults || withSastResults {
		targetResults.JasResults = &results.JasScansResults{}
		if withCaResults {
			targetResults.JasResults.ApplicabilityScanResults = []*sarif.Run{{}}
		}
		if withSecretsResult || withIacResults || withSastResults {
			targetResults.JasResults.JasVulnerabilities = results.JasScanResults{}
			if withSecretsResult {
				targetResults.JasResults.JasVulnerabilities.SecretsScanResults = []*sarif.Run{{}}
			}
			if withIacResults {
				targetResults.JasResults.JasVulnerabilities.IacScanResults = []*sarif.Run{{}}
			}
			if withSastResults {
				targetResults.JasResults.JasVulnerabilities.SastScanResults = []*sarif.Run{{}}
			}
		}
	}

	targetResults.ResultsStatus = results.ResultsStatus{
		ScaScanStatusCode:            intPtr(scaStatusCode),
		ContextualAnalysisStatusCode: intPtr(caStatusCode),
		SecretsScanStatusCode:        intPtr(secretsStatusCode),
		IacScanStatusCode:            intPtr(iacStatusCode),
		SastScanStatusCode:           intPtr(sastStatusCode),
	}

	result := &results.SecurityCommandResults{
		Targets:              []*results.TargetResults{targetResults},
		ViolationsStatusCode: intPtr(violationsStatusCode),
	}

	if withViolations {
		result.Violations = &violationutils.Violations{
			Sca:     []violationutils.CveViolation{{}},
			Secrets: []violationutils.JasViolation{{}},
			Iac:     []violationutils.JasViolation{{}},
			Sast:    []violationutils.JasViolation{{}},
		}
	}

	return result
}
