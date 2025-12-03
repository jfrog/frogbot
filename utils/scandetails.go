package utils

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/policy/enforcer"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin"
	"github.com/jfrog/jfrog-cli-security/sca/scan/enrich"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
)

type ScanDetails struct {
	*Project
	*Git

	*xscservices.XscGitInfoContext
	*config.ServerDetails
	client              vcsclient.VcsClient
	fixableOnly         bool
	disableJas          bool
	minSeverityFilter   severityutils.Severity
	baseBranch          string
	configProfile       *xscservices.ConfigProfile
	allowPartialResults bool

	diffScan         bool
	ResultsToCompare *results.SecurityCommandResults

	results.ResultContext
	MultiScanId string
	XrayVersion string
	XscVersion  string
	StartTime   time.Time
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

func (sc *ScanDetails) SetDisableJas(disable bool) *ScanDetails {
	sc.disableJas = disable
	return sc
}

func (sc *ScanDetails) SetProject(project *Project) *ScanDetails {
	sc.Project = project
	return sc
}

func (sc *ScanDetails) SetResultsContext(httpCloneUrl string, watches []string, jfrogProjectKey string, includeVulnerabilities, includeLicenses bool) *ScanDetails {
	sc.ResultContext = audit.CreateAuditResultsContext(sc.ServerDetails, sc.XrayVersion, watches, sc.RepoPath, jfrogProjectKey, httpCloneUrl, includeVulnerabilities, includeLicenses, false)
	return sc
}

func (sc *ScanDetails) SetFixableOnly(fixable bool) *ScanDetails {
	sc.fixableOnly = fixable
	return sc
}

func (sc *ScanDetails) SetMinSeverity(minSeverity string) (*ScanDetails, error) {
	if minSeverity == "" {
		return sc, nil
	}
	if severity, err := severityutils.ParseSeverity(minSeverity, false); err != nil {
		return sc, err
	} else {
		sc.minSeverityFilter = severity
	}
	return sc, nil
}

func (sc *ScanDetails) SetAllowPartialResults(allowPartialResults bool) *ScanDetails {
	sc.allowPartialResults = allowPartialResults
	return sc
}

func (sc *ScanDetails) SetBaseBranch(branch string) *ScanDetails {
	sc.baseBranch = branch
	return sc
}

func (sc *ScanDetails) SetConfigProfile(configProfile *xscservices.ConfigProfile) *ScanDetails {
	sc.configProfile = configProfile
	return sc
}

func (sc *ScanDetails) Client() vcsclient.VcsClient {
	return sc.client
}

func (sc *ScanDetails) BaseBranch() string {
	return sc.baseBranch
}

func (sc *ScanDetails) FixableOnly() bool {
	return sc.fixableOnly
}

func (sc *ScanDetails) DisableJas() bool {
	return sc.disableJas
}

func (sc *ScanDetails) MinSeverityFilter() severityutils.Severity {
	return sc.minSeverityFilter
}

func (sc *ScanDetails) SetRepoOwner(owner string) *ScanDetails {
	sc.RepoOwner = owner
	return sc
}

func (sc *ScanDetails) SetRepoName(repoName string) *ScanDetails {
	sc.RepoName = repoName
	return sc
}

func (sc *ScanDetails) AllowPartialResults() bool {
	return sc.allowPartialResults
}

func (sc *ScanDetails) RunInstallAndAudit(workDirs ...string) (auditResults *results.SecurityCommandResults) {
	auditBasicParams := (&audit.AuditBasicParams{}).
		SetXrayVersion(sc.XrayVersion).
		SetXscVersion(sc.XscVersion).
		SetPipRequirementsFile(sc.PipRequirementsFile).
		SetUseWrapper(*sc.UseWrapper).
		SetMaxTreeDepth(sc.MaxPnpmTreeDepth).
		SetDepsRepo(sc.DepsRepo).
		SetIgnoreConfigFile(true).
		SetServerDetails(sc.ServerDetails).
		SetInstallCommandName(sc.InstallCommandName).
		SetInstallCommandArgs(sc.InstallCommandArgs).
		SetTechnologies(sc.GetTechFromInstallCmdIfExists()).
		SetAllowPartialResults(sc.allowPartialResults).
		SetExclusions(sc.PathExclusions).
		SetUseJas(!sc.DisableJas()).
		SetConfigProfile(sc.configProfile)

	auditParams := audit.NewAuditParams().
		SetBomGenerator(xrayplugin.NewXrayLibBomGenerator()).
		SetScaScanStrategy(enrich.NewEnrichScanStrategy()).
		SetUploadCdxResults(!sc.diffScan || sc.ResultsToCompare != nil).
		SetGitContext(sc.XscGitInfoContext).
		SetRtResultRepository(frogbotUploadRtRepoPath).
		SetWorkingDirs(workDirs).
		SetMinSeverityFilter(sc.MinSeverityFilter()).
		SetFixableOnly(sc.FixableOnly()).
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

func GetFullPathWorkingDirs(workingDirs []string, baseWd string) []string {
	var fullPathWds []string
	if len(workingDirs) != 0 {
		for _, workDir := range workingDirs {
			if workDir == RootDir {
				fullPathWds = append(fullPathWds, baseWd)
				continue
			}
			fullPathWds = append(fullPathWds, filepath.Join(baseWd, workDir))
		}
	} else {
		fullPathWds = append(fullPathWds, baseWd)
	}
	return fullPathWds
}
