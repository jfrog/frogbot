package utils

import (
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	installationCmdFailedErr = "Couldn't run the installation command on the base branch. Assuming new project in the source branch: "
)

type ScanDetails struct {
	*Project
	*services.XrayGraphScanParams
	*config.ServerDetails
	git                  *Git
	client               vcsclient.VcsClient
	failOnSecurityIssues bool
	fixableOnly          bool
	minSeverityFilter    string
}

func newScanDetails(client vcsclient.VcsClient, repository *Repository) *ScanDetails {
	if repository == nil {
		return &ScanDetails{}
	}
	scanDetails := ScanDetails{client: client, ServerDetails: &repository.Server, git: &repository.Git}
	scanDetails.SetFailOnSecurityIssues(*repository.FailOnSecurityIssues).
		SetMinSeverity(repository.MinSeverity).
		SetFixableOnly(repository.FixableOnly).
		SetXrayGraphScanParams(repository.Watches, repository.JFrogProjectKey)
	return &scanDetails
}

func (sc *ScanDetails) SetFailOnSecurityIssues(toFail bool) *ScanDetails {
	sc.failOnSecurityIssues = toFail
	return sc
}

func (sc *ScanDetails) SetProject(project *Project) *ScanDetails {
	sc.Project = project
	return sc
}

func (sc *ScanDetails) SetXrayGraphScanParams(watches []string, jfrogProjectKey string) *ScanDetails {
	sc.XrayGraphScanParams = createXrayScanParams(watches, jfrogProjectKey)
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

type RepositoryScanDetails struct {
	scanDetails *ScanDetails
	baseBranch  string
}

func NewRepositoryScanDetails(client vcsclient.VcsClient, repository *Repository) *RepositoryScanDetails {
	return &RepositoryScanDetails{scanDetails: newScanDetails(client, repository)}
}

func (rsd *RepositoryScanDetails) SetBaseBranch(branch string) *RepositoryScanDetails {
	rsd.baseBranch = branch
	return rsd
}

func (rsd *RepositoryScanDetails) BaseBranch() string {
	return rsd.baseBranch
}

func (rsd *RepositoryScanDetails) SetRepoOwner(owner string) *RepositoryScanDetails {
	rsd.scanDetails.git.RepoOwner = owner
	return rsd
}

func (rsd *RepositoryScanDetails) RepoOwner() string {
	return rsd.scanDetails.git.RepoOwner
}

func (rsd *RepositoryScanDetails) SetRepoName(repoName string) *RepositoryScanDetails {
	rsd.scanDetails.git.RepoName = repoName
	return rsd
}

func (rsd *RepositoryScanDetails) RepoName() string {
	return rsd.scanDetails.git.RepoName
}

func (rsd *RepositoryScanDetails) BranchNameTemplate() string {
	return rsd.scanDetails.git.BranchNameTemplate
}

func (rsd *RepositoryScanDetails) CommitMessageTemplate() string {
	return rsd.scanDetails.git.CommitMessageTemplate
}

func (rsd *RepositoryScanDetails) PullRequestTitleTemplate() string {
	return rsd.scanDetails.git.PullRequestTitleTemplate
}

func (rsd *RepositoryScanDetails) EmailAuthor() string {
	return rsd.scanDetails.git.EmailAuthor
}

func (rsd *RepositoryScanDetails) GitClient() vcsclient.VcsClient {
	return rsd.scanDetails.client
}

func (rsd *RepositoryScanDetails) FailOnInstallationErrors() bool {
	return rsd.scanDetails.failOnSecurityIssues
}

func (rsd *RepositoryScanDetails) FixableOnly() bool {
	return rsd.scanDetails.fixableOnly
}

func (rsd *RepositoryScanDetails) MinSeverityFilter() string {
	return rsd.scanDetails.minSeverityFilter
}

func (rsd *RepositoryScanDetails) GitProvider() vcsutils.VcsProvider {
	return rsd.scanDetails.git.GitProvider
}

func (rsd *RepositoryScanDetails) VcsInfo() vcsclient.VcsInfo {
	return rsd.scanDetails.git.VcsInfo
}

func (rsd *RepositoryScanDetails) SetAggregateFixes(toAggregate bool) *RepositoryScanDetails {
	rsd.scanDetails.git.AggregateFixes = toAggregate
	return rsd
}

func (rsd *RepositoryScanDetails) AggregateFixes() bool {
	return rsd.scanDetails.git.AggregateFixes
}

func (rsd *RepositoryScanDetails) SetProject(project *Project) *RepositoryScanDetails {
	rsd.scanDetails.Project = project
	return rsd
}

func (rsd *RepositoryScanDetails) Project() *Project {
	return rsd.scanDetails.Project
}

func (rsd *RepositoryScanDetails) SetServerDetails(serverDetails *config.ServerDetails) *RepositoryScanDetails {
	rsd.scanDetails.ServerDetails = serverDetails
	return rsd
}

func (rsd *RepositoryScanDetails) ServerDetails() *config.ServerDetails {
	return rsd.scanDetails.ServerDetails
}

func (rsd *RepositoryScanDetails) RunInstallAndAudit(workDirs ...string) (auditResults *audit.Results, err error) {
	return rsd.scanDetails.runInstallAndAudit(workDirs...)
}

type PullRequestScanDetails struct {
	scanDetails *ScanDetails
}

func NewPullRequestScanDetails(client vcsclient.VcsClient, repository *Repository) *PullRequestScanDetails {
	return &PullRequestScanDetails{scanDetails: newScanDetails(client, repository)}
}

func (prd *PullRequestScanDetails) PullRequestInfo() vcsclient.PullRequestInfo {
	return prd.scanDetails.git.PullRequestDetails
}

func (prd *PullRequestScanDetails) EmailAuthor() string {
	return prd.scanDetails.git.EmailAuthor
}

func (prd *PullRequestScanDetails) GitClient() vcsclient.VcsClient {
	return prd.scanDetails.client
}

func (prd *PullRequestScanDetails) FailOnInstallationErrors() bool {
	return prd.scanDetails.failOnSecurityIssues
}

func (prd *PullRequestScanDetails) FixableOnly() bool {
	return prd.scanDetails.fixableOnly
}

func (prd *PullRequestScanDetails) MinSeverityFilter() string {
	return prd.scanDetails.minSeverityFilter
}

func (prd *PullRequestScanDetails) GitProvider() vcsutils.VcsProvider {
	return prd.scanDetails.git.GitProvider
}

func (prd *PullRequestScanDetails) VcsInfo() vcsclient.VcsInfo {
	return prd.scanDetails.git.VcsInfo
}

func (prd *PullRequestScanDetails) SetProject(project *Project) *PullRequestScanDetails {
	prd.scanDetails.Project = project
	return prd
}

func (prd *PullRequestScanDetails) Project() *Project {
	return prd.scanDetails.Project
}

func (prd *PullRequestScanDetails) SetServerDetails(serverDetails *config.ServerDetails) *PullRequestScanDetails {
	prd.scanDetails.ServerDetails = serverDetails
	return prd
}

func (prd *PullRequestScanDetails) ServerDetails() *config.ServerDetails {
	return prd.scanDetails.ServerDetails
}

func (prd *PullRequestScanDetails) RunInstallAndAudit(workDirs ...string) (auditResults *audit.Results, err error) {
	return prd.scanDetails.runInstallAndAudit(workDirs...)
}

func createXrayScanParams(watches []string, project string) (params *services.XrayGraphScanParams) {
	params = &services.XrayGraphScanParams{
		ScanType:        services.Dependency,
		IncludeLicenses: false,
	}
	if len(watches) > 0 {
		params.Watches = watches
		return
	}
	if project != "" {
		params.ProjectKey = project
		return
	}
	// No context was supplied. We therefore request from Xray to return all known vulnerabilities.
	params.IncludeVulnerabilities = true
	return
}

func (sc *ScanDetails) runInstallAndAudit(workDirs ...string) (auditResults *audit.Results, err error) {
	for _, wd := range workDirs {
		if err = sc.runInstallIfNeeded(wd); err != nil {
			return nil, err
		}
	}

	auditBasicParams := (&xrayutils.AuditBasicParams{}).
		SetPipRequirementsFile(sc.PipRequirementsFile).
		SetUseWrapper(*sc.UseWrapper).
		SetDepsRepo(sc.DepsRepo).
		SetIgnoreConfigFile(true).
		SetServerDetails(sc.ServerDetails)

	auditParams := audit.NewAuditParams().
		SetXrayGraphScanParams(sc.XrayGraphScanParams).
		SetWorkingDirs(workDirs).
		SetMinSeverityFilter(sc.minSeverityFilter).
		SetFixableOnly(sc.fixableOnly).
		SetGraphBasicParams(auditBasicParams)

	auditResults, err = audit.RunAudit(auditParams)
	if auditResults != nil {
		err = errors.Join(err, auditResults.ScaError, auditResults.JasError)
	}
	return
}

func (sc *ScanDetails) runInstallIfNeeded(workDir string) (err error) {
	if sc.InstallCommandName == "" {
		return nil
	}
	restoreDir, err := Chdir(workDir)
	defer func() {
		err = errors.Join(err, restoreDir())
	}()
	log.Info(fmt.Sprintf("Executing '%s %s' at %s", sc.InstallCommandName, strings.Join(sc.InstallCommandArgs, " "), workDir))
	output, err := sc.runInstallCommand()
	if err != nil && !sc.failOnSecurityIssues {
		log.Info(installationCmdFailedErr, err.Error(), "\n", string(output))
		// failOnSecurityIssues set to 'false'
		err = nil
	}
	return
}

func (sc *ScanDetails) runInstallCommand() ([]byte, error) {
	if sc.DepsRepo == "" {
		//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
		return exec.Command(sc.InstallCommandName, sc.InstallCommandArgs...).CombinedOutput()
	}

	if _, exists := MapTechToResolvingFunc[sc.InstallCommandName]; !exists {
		return nil, fmt.Errorf(sc.InstallCommandName, "isn't recognized as an install command")
	}
	log.Info("Resolving dependencies from", sc.ServerDetails.Url, "from repo", sc.DepsRepo)
	return MapTechToResolvingFunc[sc.InstallCommandName](sc)
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
