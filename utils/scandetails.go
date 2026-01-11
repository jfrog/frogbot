package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/policy/enforcer"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/sca/scan/enrich"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type ScanDetails struct {
	*Git

	*xscservices.XscGitInfoContext
	*config.ServerDetails
	client           vcsclient.VcsClient
	baseBranch       string
	diffScan         bool
	ResultsToCompare *results.SecurityCommandResults
	ConfigProfile    *xscservices.ConfigProfile

	// scansToPerform limits which scan types to run (for parallel scanning)
	scansToPerform []utils.SubScanType

	// uploadCdxResults controls whether to upload results to the platform
	// nil means use default logic (based on diffScan and ResultsToCompare)
	uploadCdxResults *bool

	// logCollector captures all logs for this scan in an isolated buffer.
	// When set, logs are not interleaved with other parallel scans.
	logCollector *audit.LogCollector

	results.ResultContext
	MultiScanId string
	XrayVersion string
	XscVersion  string
	StartTime   time.Time
}

// Clone creates a copy of ScanDetails for parallel scanning.
// Note: logCollector is NOT cloned - each parallel scan should have its own collector.
func (sc *ScanDetails) Clone() *ScanDetails {
	return &ScanDetails{
		Git:               sc.Git,
		XscGitInfoContext: sc.XscGitInfoContext,
		ServerDetails:     sc.ServerDetails,
		client:            sc.client,
		baseBranch:        sc.baseBranch,
		diffScan:          sc.diffScan,
		ResultsToCompare:  sc.ResultsToCompare,
		ConfigProfile:     sc.ConfigProfile,
		scansToPerform:   sc.scansToPerform,
		uploadCdxResults: sc.uploadCdxResults,
		// logCollector intentionally not cloned - each scan needs its own
		ResultContext: sc.ResultContext,
		MultiScanId:   sc.MultiScanId,
		XrayVersion:   sc.XrayVersion,
		XscVersion:    sc.XscVersion,
		StartTime:     sc.StartTime,
	}
}

func (sc *ScanDetails) SetScansToPerform(scans []utils.SubScanType) *ScanDetails {
	sc.scansToPerform = scans
	return sc
}

// SetUploadCdxResults explicitly controls whether to upload results to the platform
// Pass false to disable uploading for intermediate parallel scans
func (sc *ScanDetails) SetUploadCdxResults(upload bool) *ScanDetails {
	sc.uploadCdxResults = &upload
	return sc
}

// SetLogCollector sets a log collector for isolated log capture.
// When set, all logs from this scan are captured in the collector's buffer,
// enabling parallel scans to have completely isolated logs.
// Use GetLogCollector().GetLogs() after the scan to retrieve the captured logs.
func (sc *ScanDetails) SetLogCollector(collector *audit.LogCollector) *ScanDetails {
	sc.logCollector = collector
	return sc
}

// GetLogCollector returns the log collector, or nil if not set.
func (sc *ScanDetails) GetLogCollector() *audit.LogCollector {
	return sc.logCollector
}

func NewScanDetails(client vcsclient.VcsClient, server *config.ServerDetails, git *Git) *ScanDetails {
	return &ScanDetails{client: client, ServerDetails: server, Git: git}
}

func (sc *ScanDetails) SetJfrogVersions(xrayVersion, xscVersion string) *ScanDetails {
	sc.XrayVersion = xrayVersion
	sc.XscVersion = xscVersion
	return sc
}

func (sc *ScanDetails) SetDiffScan(diffScan bool) *ScanDetails {
	sc.diffScan = diffScan
	return sc
}

func (sc *ScanDetails) SetResultsToCompare(results *results.SecurityCommandResults) *ScanDetails {
	sc.ResultsToCompare = results
	return sc
}

func (sc *ScanDetails) SetResultsContext(httpCloneUrl string, jfrogProjectKey string, includeVulnerabilities bool) *ScanDetails {
	sc.ResultContext = audit.CreateAuditResultsContext(sc.ServerDetails, sc.XrayVersion, []string{}, sc.RepoPath, jfrogProjectKey, httpCloneUrl, includeVulnerabilities, true, false)
	return sc
}

func (sc *ScanDetails) SetBaseBranch(branch string) *ScanDetails {
	sc.baseBranch = branch
	return sc
}

func (sc *ScanDetails) SetConfigProfile(configProfile *xscservices.ConfigProfile) *ScanDetails {
	sc.ConfigProfile = configProfile
	return sc
}

func (sc *ScanDetails) Client() vcsclient.VcsClient {
	return sc.client
}

func (sc *ScanDetails) BaseBranch() string {
	return sc.baseBranch
}

func (sc *ScanDetails) SetRepoOwner(owner string) *ScanDetails {
	sc.RepoOwner = owner
	return sc
}

func (sc *ScanDetails) SetRepoName(repoName string) *ScanDetails {
	sc.RepoName = repoName
	return sc
}

func (sc *ScanDetails) Audit(workDirs ...string) (auditResults *results.SecurityCommandResults) {
	auditBasicParams := (&audit.AuditBasicParams{}).
		SetXrayVersion(sc.XrayVersion).
		SetXscVersion(sc.XscVersion).
		SetServerDetails(sc.ServerDetails).
		SetAllowPartialResults(!sc.ConfigProfile.GeneralConfig.FailUponAnyScannerError).
		SetExclusions(sc.ConfigProfile.GeneralConfig.GeneralExcludePatterns).
		SetUseJas(true).
		SetConfigProfile(sc.ConfigProfile).
		SetScansToPerform(sc.scansToPerform)

	// Set log collector for isolated log capture
	if sc.logCollector != nil {
		auditBasicParams.SetLogCollector(sc.logCollector)
	}

	// Determine whether to upload CDX results
	// If explicitly set, use that value; otherwise use default logic
	shouldUpload := !sc.diffScan || sc.ResultsToCompare != nil
	if sc.uploadCdxResults != nil {
		shouldUpload = *sc.uploadCdxResults
	}

	auditParams := audit.NewAuditParams().
		SetBomGenerator(xrayplugin.NewXrayLibBomGenerator()).
		SetScaScanStrategy(enrich.NewEnrichScanStrategy()).
		SetUploadCdxResults(shouldUpload).
		SetGitContext(sc.XscGitInfoContext).
		SetRtResultRepository(FrogbotUploadRtRepoPath).
		SetWorkingDirs(workDirs).
		SetGraphBasicParams(auditBasicParams).
		SetResultsContext(sc.ResultContext).
		SetDiffMode(sc.diffScan).
		SetResultsToCompare(sc.ResultsToCompare).
		SetMultiScanId(sc.MultiScanId).
		SetThreads(MaxConcurrentScanners).
		SetStartTime(sc.StartTime).
		SetViolationGenerator(enforcer.NewPolicyEnforcerViolationGenerator())

	return audit.RunAudit(auditParams)
}

// For Repo-Scan
func (sc *ScanDetails) SetXscGitInfoContext(scannedBranch, gitProject string, client vcsclient.VcsClient) *ScanDetails {
	XscGitInfoContext, err := sc.createGitInfoContext(scannedBranch, gitProject, client, nil)
	if err != nil {
		log.Debug("Failed to create a GitInfoContext for Xsc due to the following error:", err.Error())
		return sc
	}
	sc.XscGitInfoContext = XscGitInfoContext
	return sc
}

// For PR-Scan
func (sc *ScanDetails) SetXscPRGitInfoContext(gitProject string, client vcsclient.VcsClient, prDetails vcsclient.PullRequestInfo) *ScanDetails {
	XscGitInfoContext, err := sc.createGitInfoContext(prDetails.Source.Name, gitProject, client, &prDetails)
	if err != nil {
		log.Debug("Failed to create a GitInfoContext for Xsc due to the following error:", err.Error())
		return sc
	}
	sc.XscGitInfoContext = XscGitInfoContext
	return sc
}

// CreateGitInfoContext Creates GitInfoContext for XSC scans, this is optional.
// ScannedBranch - name of the branch we are scanning.
// GitProject - [Optional] relevant for azure repos and Bitbucket server.
// prDetails - if the scan is for a PR, the details of the PR.
func (sc *ScanDetails) createGitInfoContext(scannedBranch, gitProject string, client vcsclient.VcsClient, prDetails *vcsclient.PullRequestInfo) (gitInfo *xscservices.XscGitInfoContext, err error) {
	sourceCommit, err := sc.getCommitContext(scannedBranch, gitProject, client)
	if err != nil {
		return nil, err
	}
	// Get Source commit details.
	gitInfo = &xscservices.XscGitInfoContext{
		Source:      sourceCommit,
		GitProvider: sc.Git.GitProvider.String(),
	}
	if prDetails == nil {
		return
	}
	// PR context
	gitInfo.PullRequest = &xscservices.PullRequestContext{
		PullRequestId:    int(prDetails.ID),
		PullRequestTitle: prDetails.Title,
	}
	// Target details are available, get target commit details.
	targetInfo, err := sc.getCommitContext(prDetails.Target.Name, gitProject, client)
	if err != nil {
		return nil, err
	}
	gitInfo.Target = &targetInfo
	return
}

func (sc *ScanDetails) getCommitContext(scannedBranch, gitProject string, client vcsclient.VcsClient) (commitContext xscservices.CommitContext, err error) {
	latestCommit, err := client.GetLatestCommit(context.Background(), sc.RepoOwner, sc.RepoName, scannedBranch)
	if err != nil {
		return xscservices.CommitContext{}, fmt.Errorf("failed getting latest commit, repository: %s, branch: %s. error: %s ", sc.RepoName, scannedBranch, err.Error())
	}
	// In some VCS providers, there are no git projects, fallback to the repository owner.
	if gitProject == "" {
		gitProject = sc.RepoOwner
	}
	commitContext = xscservices.CommitContext{
		// Use Clone URLs as Repo Url, on browsers it will redirect to repository URLS.
		GitRepoHttpsCloneUrl: sc.Git.RepositoryCloneUrl,
		GitRepoName:          sc.RepoName,
		GitProject:           gitProject,
		BranchName:           scannedBranch,
		CommitHash:           latestCommit.Hash,
		CommitMessage:        latestCommit.Message,
		CommitAuthor:         latestCommit.AuthorName,
	}
	return
}
