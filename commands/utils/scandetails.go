package utils

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type ScanDetails struct {
	*Project
	*Git
	*services.XrayGraphScanParams
	*config.ServerDetails
	client                   vcsclient.VcsClient
	failOnInstallationErrors bool
	withFixVersionFilter     bool
	minSeverityFilter        string
	branch                   string
	releasesRepo             string
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

func (sc *ScanDetails) SetXrayGraphScanParams(watches []string, jfrogProjectKey string) *ScanDetails {
	sc.XrayGraphScanParams = createXrayScanParams(watches, jfrogProjectKey)
	return sc
}

func (sc *ScanDetails) SetWithFixVersionFilter(withFixVersionFilter bool) *ScanDetails {
	sc.withFixVersionFilter = withFixVersionFilter
	return sc
}

func (sc *ScanDetails) SetMinSeverityFilter(minSeverityFilter string) *ScanDetails {
	sc.minSeverityFilter = minSeverityFilter
	return sc
}

func (sc *ScanDetails) SetBranch(branch string) *ScanDetails {
	sc.branch = branch
	return sc
}

func (sc *ScanDetails) SetReleasesRepo(releasesRepo string) *ScanDetails {
	sc.releasesRepo = releasesRepo
	return sc
}

func (sc *ScanDetails) Client() vcsclient.VcsClient {
	return sc.client
}

func (sc *ScanDetails) Branch() string {
	return sc.branch
}

func (sc *ScanDetails) ReleasesRepo() string {
	return sc.releasesRepo
}

func (sc *ScanDetails) FailOnInstallationErrors() bool {
	return sc.failOnInstallationErrors
}

func (sc *ScanDetails) WithFixVersionFilter() bool {
	return sc.withFixVersionFilter
}

func (sc *ScanDetails) MinSeverityFilter() string {
	return sc.minSeverityFilter
}

func createXrayScanParams(watches []string, project string) (params *services.XrayGraphScanParams) {
	params = &services.XrayGraphScanParams{}
	params.ScanType = services.Dependency
	params.IncludeLicenses = false
	if len(watches) > 0 {
		params.Watches = watches
		return
	}
	if project != "" {
		params.ProjectKey = project
		return
	}
	// No context was supplied, request from Xray to return all known vulnerabilities.
	params.IncludeVulnerabilities = true
	return
}
