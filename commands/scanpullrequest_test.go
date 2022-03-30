package commands

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient

func TestCreateXrayScanParams(t *testing.T) {
	// Project
	params := createXrayScanParams("", "")
	assert.Empty(t, params.Watches)
	assert.Equal(t, "", params.ProjectKey)
	assert.True(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)

	// Watches
	params = createXrayScanParams("watch-1,watch-2", "")
	assert.Equal(t, []string{"watch-1", "watch-2"}, params.Watches)
	assert.Equal(t, "", params.ProjectKey)
	assert.False(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)

	// Project
	params = createXrayScanParams("", "project")
	assert.Empty(t, params.Watches)
	assert.Equal(t, "project", params.ProjectKey)
	assert.False(t, params.IncludeVulnerabilities)
	assert.False(t, params.IncludeLicenses)
}

func TestGetNewViolations(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := services.ScanResponse{
		Violations: []services.Violation{{
			IssueId:       "XRAY-1",
			Summary:       "summary-1",
			Severity:      "high",
			ViolationType: "security",
			Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run getNewViolations and make sure that only the XRAY-2 violation exists in the results
	newViolations := getNewViolations(previousScan, currentScan)
	assert.Len(t, newViolations, 2)
	assert.Equal(t, "XRAY-2", newViolations[0].IssueId)
	assert.Equal(t, "low", newViolations[0].Severity)
	assert.Equal(t, "XRAY-2", newViolations[1].IssueId)
	assert.Equal(t, "low", newViolations[1].Severity)

	impactedPackageOne := newViolations[0].ImpactedPackageName
	impactedPackageTwo := newViolations[1].ImpactedPackageName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestGetNewViolationsCaseNoPrevViolations(t *testing.T) {
	// Previous scan with no violation
	previousScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
		},
	}

	// Run getNewViolations and expect both XRAY-1 and XRAY-2 violation in the results
	newViolations := getNewViolations(previousScan, currentScan)
	assert.Len(t, newViolations, 2)
	assert.Equal(t, "XRAY-1", newViolations[0].IssueId)
	assert.Equal(t, "high", newViolations[0].Severity)
	assert.Equal(t, "component-A", newViolations[0].ImpactedPackageName)
	assert.Equal(t, "XRAY-2", newViolations[1].IssueId)
	assert.Equal(t, "low", newViolations[1].Severity)
	assert.Equal(t, "component-C", newViolations[1].ImpactedPackageName)
}

func TestGetNewViolationsCaseNoNewViolations(t *testing.T) {
	// Previous scan with 2 violations - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
		},
	}

	// Current scan with no violation
	currentScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Run getNewViolations and expect no violations in the results
	newViolations := getNewViolations(previousScan, currentScan)
	assert.Len(t, newViolations, 0)
}

func TestGetNewVulnerabilities(t *testing.T) {
	// Previous scan with only one vulnerability - XRAY-1
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
		}},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
			},
		},
	}

	// Run getNewVulnerabilities and make sure that only the XRAY-2 vulnerability exists in the results
	newViolations := getNewVulnerabilities(previousScan, currentScan)
	assert.Len(t, newViolations, 2)
	assert.Equal(t, "XRAY-2", newViolations[0].IssueId)
	assert.Equal(t, "low", newViolations[0].Severity)
	assert.Equal(t, "XRAY-2", newViolations[1].IssueId)
	assert.Equal(t, "low", newViolations[1].Severity)

	impactedPackageOne := newViolations[0].ImpactedPackageName
	impactedPackageTwo := newViolations[1].ImpactedPackageName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestGetNewVulnerabilitiesCaseNoPrevVulnerabilities(t *testing.T) {
	// Previous scan with no vulnerabilities
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Run getNewVulnerabilities and expect both XRAY-1 and XRAY-2 vulnerability in the results
	newViolations := getNewVulnerabilities(previousScan, currentScan)
	assert.Len(t, newViolations, 2)
	assert.Equal(t, "XRAY-1", newViolations[0].IssueId)
	assert.Equal(t, "high", newViolations[0].Severity)
	assert.Equal(t, "component-A", newViolations[0].ImpactedPackageName)
	assert.Equal(t, "XRAY-2", newViolations[1].IssueId)
	assert.Equal(t, "low", newViolations[1].Severity)
	assert.Equal(t, "component-B", newViolations[1].ImpactedPackageName)
}

func TestGetNewVulnerabilitiesCaseNoNewVulnerabilities(t *testing.T) {
	// Previous scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no vulnerabilities
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Run getNewVulnerabilities and expect no vulnerability in the results
	newViolations := getNewVulnerabilities(previousScan, currentScan)
	assert.Len(t, newViolations, 0)
}

var params = &utils.FrogbotParams{
	GitParam: utils.GitParam{
		RepoOwner:     "repo-owner",
		Repo:          "repo-name",
		PullRequestID: 5,
	},
}

func TestBeforeScan(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Label is expected to exist in pull request
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(&vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelDescription),
	}, nil)
	client.EXPECT().ListPullRequestLabels(context.Background(), params.RepoOwner, params.Repo, params.PullRequestID).Return([]string{string(utils.LabelName)}, nil)
	client.EXPECT().UnlabelPullRequest(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName), 5).Return(nil)

	// Run beforeScan
	err := beforeScan(params, client)
	assert.NoError(t, err, utils.ErrUnlabel)
}

func TestBeforeScanLabelNotExist(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Label is expected to not exists
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(nil, nil)
	client.EXPECT().CreateLabel(context.Background(), params.RepoOwner, params.Repo, vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelColor),
	}).Return(nil)

	// Run beforeScan
	err := beforeScan(params, client)
	assert.ErrorIs(t, err, utils.ErrLabelCreated)
}

func TestBeforeScanUnlabeled(t *testing.T) {
	// Init mock
	client, finish := mockVcsClient(t)
	defer finish()

	// Pull request is expected to be unlabeled
	client.EXPECT().GetLabel(context.Background(), params.RepoOwner, params.Repo, string(utils.LabelName)).Return(&vcsclient.LabelInfo{
		Name:        string(utils.LabelName),
		Description: string(utils.LabelDescription),
		Color:       string(utils.LabelDescription),
	}, nil)
	client.EXPECT().ListPullRequestLabels(context.Background(), params.RepoOwner, params.Repo, params.PullRequestID).Return([]string{}, nil)

	// Run beforeScan
	err := beforeScan(params, client)
	assert.ErrorIs(t, err, utils.ErrUnlabel)
}

func mockVcsClient(t *testing.T) (*testdata.MockVcsClient, func()) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	return testdata.NewMockVcsClient(mockCtrl), mockCtrl.Finish
}

func TestCreatePullRequestMessageNoVulnerabilities(t *testing.T) {
	vulnerabilities := []xrayutils.VulnerabilityRow{}
	message := createPullRequestMessage(vulnerabilities)

	expectedMessage, err := os.ReadFile(filepath.Join("testdata", "messages", "novulnerabilities.md"))
	assert.NoError(t, err)
	assert.Equal(t, string(expectedMessage), message)

}

func TestCreatePullRequestMessage(t *testing.T) {
	vulnerabilities := []xrayutils.VulnerabilityRow{
		{
			Severity:               "High",
			ImpactedPackageName:    "github.com/nats-io/nats-streaming-server",
			ImpactedPackageVersion: "v0.21.0",
			FixedVersions:          "[0.24.1]",
			Components: []xrayutils.ComponentRow{
				{
					Name:    "github.com/nats-io/nats-streaming-server",
					Version: "v0.21.0",
				},
			},
			Cves: []xrayutils.CveRow{{Id: "CVE-2022-24450"}},
		},
		{
			Severity:               "High",
			ImpactedPackageName:    "github.com/mholt/archiver/v3",
			ImpactedPackageVersion: "v3.5.1",
			Components: []xrayutils.ComponentRow{
				{
					Name:    "github.com/mholt/archiver/v3",
					Version: "v3.5.1",
				},
			},
			Cves: []xrayutils.CveRow{},
		},
		{
			Severity:               "Medium",
			ImpactedPackageName:    "github.com/nats-io/nats-streaming-server",
			ImpactedPackageVersion: "v0.21.0",
			FixedVersions:          "[0.24.3]",
			Components: []xrayutils.ComponentRow{
				{
					Name:    "github.com/nats-io/nats-streaming-server",
					Version: "v0.21.0",
				},
			},
			Cves: []xrayutils.CveRow{{Id: "CVE-2022-26652"}},
		},
	}
	message := createPullRequestMessage(vulnerabilities)

	expectedMessage, err := os.ReadFile(filepath.Join("testdata", "messages", "dummyvulnerabilities.md"))
	assert.NoError(t, err)
	assert.Equal(t, string(expectedMessage), message)

}
