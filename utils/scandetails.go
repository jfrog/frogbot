package utils

import (
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"

	"os/exec"
	"strings"
)

const (
	installationCmdFailedMsg = "Couldn't run the installation command on the base branch. Assuming new project in the source branch: "
)

type ScanDetails struct {
	project              Project
	xrayGraphScanParams  services.XrayGraphScanParams
	serverDetails        config.ServerDetails
	git                  Git
	client               vcsclient.VcsClient
	failOnSecurityIssues bool
	fixableOnly          bool
	minSeverityFilter    string
}

func newScanDetails(client vcsclient.VcsClient, repository *Repository) *ScanDetails {
	if repository == nil {
		return &ScanDetails{}
	}
	scanDetails := ScanDetails{client: client, serverDetails: repository.Server, git: repository.Git}
	scanDetails.SetFailOnSecurityIssues(*repository.FailOnSecurityIssues).
		SetMinSeverity(repository.MinSeverity).
		SetFixableOnly(repository.FixableOnly).
		SetXrayGraphScanParams(repository.Watches, repository.JFrogProjectKey)
	return &scanDetails
}

func (sc *ScanDetails) Project() *Project {
	return &sc.project
}

func (sc *ScanDetails) XrayGraphScanParams() *services.XrayGraphScanParams {
	return &sc.xrayGraphScanParams
}

func (sc *ScanDetails) ServerDetails() *config.ServerDetails {
	return &sc.serverDetails
}

func (sc *ScanDetails) GitClient() vcsclient.VcsClient {
	return sc.client
}

func (sc *ScanDetails) FailOnSecurityIssues() bool {
	return sc.failOnSecurityIssues
}

func (sc *ScanDetails) FixableOnly() bool {
	return sc.fixableOnly
}

func (sc *ScanDetails) MinSeverityFilter() string {
	return sc.minSeverityFilter
}

func (sc *ScanDetails) SetMinSeverityFilter(minSeverityFilter string) *ScanDetails {
	sc.minSeverityFilter = minSeverityFilter
	return sc
}

func (sc *ScanDetails) SetFailOnSecurityIssues(toFail bool) *ScanDetails {
	sc.failOnSecurityIssues = toFail
	return sc
}

func (sc *ScanDetails) SetProject(project *Project) *ScanDetails {
	sc.project = *project
	return sc
}

func (sc *ScanDetails) SetXrayGraphScanParams(watches []string, jfrogProjectKey string) *ScanDetails {
	sc.xrayGraphScanParams = *createXrayScanParams(watches, jfrogProjectKey)
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

func (sc *ScanDetails) SetServerDetails(serverDetails *config.ServerDetails) *ScanDetails {
	sc.serverDetails = *serverDetails
	return sc
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

func (sc *ScanDetails) RunInstallAndAudit(workDirs ...string) (auditResults *audit.Results, err error) {
	for _, wd := range workDirs {
		if err = sc.runInstallIfNeeded(wd); err != nil {
			return nil, err
		}
	}

	auditBasicParams := (&xrayutils.AuditBasicParams{}).
		SetPipRequirementsFile(sc.project.PipRequirementsFile).
		SetUseWrapper(*sc.project.UseWrapper).
		SetDepsRepo(sc.project.DepsRepo).
		SetIgnoreConfigFile(true).
		SetServerDetails(&sc.serverDetails)

	auditParams := audit.NewAuditParams().
		SetXrayGraphScanParams(&sc.xrayGraphScanParams).
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
	if sc.project.InstallCommandName == "" {
		return nil
	}
	restoreDir, err := Chdir(workDir)
	defer func() {
		err = errors.Join(err, restoreDir())
	}()
	log.Info(fmt.Sprintf("Executing '%s %s' at %s", sc.project.InstallCommandName, strings.Join(sc.project.InstallCommandArgs, " "), workDir))
	output, err := sc.runInstallCommand()
	if err != nil && !sc.failOnSecurityIssues {
		log.Info(installationCmdFailedMsg, err.Error(), "\n", string(output))
		// failOnSecurityIssues set to 'false'
		err = nil
	}
	return
}

func (sc *ScanDetails) runInstallCommand() ([]byte, error) {
	if sc.project.DepsRepo == "" {
		//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
		return exec.Command(sc.project.InstallCommandName, sc.project.InstallCommandArgs...).CombinedOutput()
	}

	if _, exists := MapTechToResolvingFunc[sc.project.InstallCommandName]; !exists {
		return nil, fmt.Errorf(sc.project.InstallCommandName, "isn't recognized as an install command")
	}
	log.Info("Resolving dependencies from", sc.serverDetails.Url, "from repo", sc.project.DepsRepo)
	return MapTechToResolvingFunc[sc.project.InstallCommandName](sc)
}
