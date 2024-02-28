package utils

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/utils"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"path/filepath"
)

type ScanDetails struct {
	*Project
	*Git
	*services.XrayGraphScanParams
	*config.ServerDetails
	client                   vcsclient.VcsClient
	failOnInstallationErrors bool
	fixableOnly              bool
	minSeverityFilter        string
	baseBranch               string
}

func NewScanDetails(client vcsclient.VcsClient, server *config.ServerDetails, git *Git) *ScanDetails {
	return &ScanDetails{client: client, ServerDetails: server, Git: git}
}

func (sc *ScanDetails) SetFailOnInstallationErrors(toFail bool) *ScanDetails {
	sc.failOnInstallationErrors = toFail
	return sc
}

func (sc *ScanDetails) SetProject(project *Project) *ScanDetails {
	sc.Project = project
	return sc
}

func (sc *ScanDetails) SetXrayGraphScanParams(watches []string, jfrogProjectKey string, includeLicenses bool) *ScanDetails {
	sc.XrayGraphScanParams = createXrayScanParams(watches, jfrogProjectKey, includeLicenses)
	return sc
}

func (sc *ScanDetails) SetFixableOnly(fixable bool) *ScanDetails {
	sc.fixableOnly = fixable
	return sc
}

func (sc *ScanDetails) SetMinSeverity(minSeverity string) *ScanDetails {
	sc.minSeverityFilter = minSeverity
	return sc
}

func (sc *ScanDetails) SetBaseBranch(branch string) *ScanDetails {
	sc.baseBranch = branch
	return sc
}

func (sc *ScanDetails) Client() vcsclient.VcsClient {
	return sc.client
}

func (sc *ScanDetails) BaseBranch() string {
	return sc.baseBranch
}

func (sc *ScanDetails) FailOnInstallationErrors() bool {
	return sc.failOnInstallationErrors
}

func (sc *ScanDetails) FixableOnly() bool {
	return sc.fixableOnly
}

func (sc *ScanDetails) MinSeverityFilter() string {
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

func createXrayScanParams(watches []string, project string, includeLicenses bool) (params *services.XrayGraphScanParams) {
	params = &services.XrayGraphScanParams{
		ScanType:        services.Dependency,
		IncludeLicenses: includeLicenses,
	}
	if len(watches) > 0 {
		params.Watches = watches
		return
	}
	if project != "" {
		params.ProjectKey = project
		return
	}
	params.IncludeVulnerabilities = true
	return
}

func (sc *ScanDetails) RunInstallAndAudit(workDirs ...string) (auditResults *xrayutils.Results, err error) {
	auditBasicParams := (&xrayutils.AuditBasicParams{}).
		SetPipRequirementsFile(sc.PipRequirementsFile).
		SetUseWrapper(*sc.UseWrapper).
		SetDepsRepo(sc.DepsRepo).
		SetIgnoreConfigFile(true).
		SetServerDetails(sc.ServerDetails).
		SetInstallCommandName(sc.InstallCommandName).
		SetInstallCommandArgs(sc.InstallCommandArgs)

	auditParams := audit.NewAuditParams().
		SetXrayGraphScanParams(sc.XrayGraphScanParams).
		SetWorkingDirs(workDirs).
		SetMinSeverityFilter(sc.MinSeverityFilter()).
		SetFixableOnly(sc.FixableOnly()).
		SetGraphBasicParams(auditBasicParams)

	auditParams.SetExclusions(sc.PathExclusions).SetIsRecursiveScan(sc.IsRecursiveScan)

	auditResults, err = audit.RunAudit(auditParams)
	if auditResults != nil {
		err = errors.Join(err, auditResults.ScaError, auditResults.JasError)
	}
	return
}

func (sc *ScanDetails) SetXscGitInfoContext(scannedBranch, gitProject string, client vcsclient.VcsClient) *ScanDetails {
	XscGitInfoContext, err := sc.createGitInfoContext(scannedBranch, gitProject, client)
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
// Client vscClient
func (sc *ScanDetails) createGitInfoContext(scannedBranch, gitProject string, client vcsclient.VcsClient) (gitInfo *services.XscGitInfoContext, err error) {
	latestCommit, err := client.GetLatestCommit(context.Background(), sc.RepoOwner, sc.RepoName, scannedBranch)
	if err != nil {
		return nil, fmt.Errorf("failed getting latest commit, repository: %s, branch: %s. error: %s ", sc.RepoName, scannedBranch, err.Error())
	}
	// In some VCS providers, there are no git projects, fallback to the repository owner.
	if gitProject == "" {
		gitProject = sc.RepoOwner
	}
	gitInfo = &services.XscGitInfoContext{
		// Use Clone URLs as Repo Url, on browsers it will redirect to repository URLS.
		GitRepoUrl:    sc.Git.RepositoryCloneUrl,
		GitRepoName:   sc.RepoName,
		GitProvider:   sc.GitProvider.String(),
		GitProject:    gitProject,
		BranchName:    scannedBranch,
		LastCommit:    latestCommit.Url,
		CommitHash:    latestCommit.Hash,
		CommitMessage: latestCommit.Message,
		CommitAuthor:  latestCommit.AuthorName,
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

func (sc *ScanDetails) CreateMultiScanIdForScans() error {
	xrayManager, err := xrayutils.CreateXrayServiceManager(sc.ServerDetails)
	if err != nil {
		return err
	}
	if err = utils.SendXscGitInfoRequestIfEnabled(sc.XrayGraphScanParams, xrayManager); err != nil {
		return err
	}
	return nil
}
