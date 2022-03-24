package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	clitool "github.com/urfave/cli/v2"
)

func ScanPullRequest(c *clitool.Context) error {
	params, client, err := getParamsAndClient(true)
	if err != nil {
		return err
	}

	// Audit PR code
	xrayScanParams := createXrayScanParams(params.watches, params.project)
	currentScan, err := auditSource(xrayScanParams, &params.server)
	if err != nil {
		return err
	}

	// Audit target code
	previousScan, err := auditTarget(client, xrayScanParams, &params.server, params.repoOwner, params.repo, params.baseBranch)
	if err != nil {
		return err
	}
	// Get only the new issues added by this PR
	var vulnerabilitiesRows []xrayutils.VulnerabilityRow
	for i := 0; i < len(currentScan); i += 1 {
		if len(currentScan[i].Violations) > 0 {
			vulnerabilitiesRows = append(vulnerabilitiesRows, getNewViolations(previousScan[i], currentScan[i])...)
		} else if len(currentScan[i].Vulnerabilities) > 0 {
			vulnerabilitiesRows = append(vulnerabilitiesRows, getNewVulnerabilities(previousScan[i], currentScan[i])...)
		}
	}
	// Comment frogbot message on the PR
	message := createPullRequestMessage(vulnerabilitiesRows)
	return client.AddPullRequestComment(context.Background(), params.repoOwner, params.repo, message, params.pullRequestID)
}

func createXrayScanParams(watches, project string) (params services.XrayGraphScanParams) {
	params.ScanType = services.Dependency
	params.IncludeLicenses = false
	if watches != "" {
		params.Watches = strings.Split(watches, watchesDelimiter)
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

func auditSource(xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails) ([]services.ScanResponse, error) {
	wd, err := os.Getwd()
	if err != nil {
		return []services.ScanResponse{}, err
	}
	clientLog.Info("Auditing " + wd)
	return runAudit(xrayScanParams, server, wd)
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails, owner, repo, branch string) (res []services.ScanResponse, err error) {
	clientLog.Info("Auditing " + repo + " " + branch)
	// First download the target repo to temp dir
	tempWorkdir, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	clientLog.Debug("Created temp working directory: " + tempWorkdir)
	defer fileutils.RemoveTempDir(tempWorkdir)
	clientLog.Debug(fmt.Sprintf("Downloading %s/%s , branch:%s to:%s", owner, repo, branch, tempWorkdir))
	err = client.DownloadRepository(context.Background(), owner, repo, branch, tempWorkdir)
	if err != nil {
		return
	}
	clientLog.Debug("Downloaded target repository")
	return runAudit(xrayScanParams, server, tempWorkdir)
}

func runAudit(xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails, workDir string) ([]services.ScanResponse, error) {
	restoreDir, err := chdir(workDir)
	if err != nil {
		return []services.ScanResponse{}, err
	}
	defer restoreDir()
	return audit.GenericAudit(xrayScanParams, server, false, false, false, []string{})
}

func getNewViolations(previousScan, currentScan services.ScanResponse) (newViolationsRows []xrayutils.VulnerabilityRow) {
	existsViolationsMap := make(map[string]xrayutils.VulnerabilityRow)
	violationsRows, _, err := xrayutils.CreateViolationsRows(previousScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, err = xrayutils.CreateViolationsRows(currentScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[getUniqueID(violation)]; !exists {
			newViolationsRows = append(newViolationsRows, violation)
		}
	}
	return
}

func getNewVulnerabilities(previousScan, currentScan services.ScanResponse) (newVulnerabilitiesRows []xrayutils.VulnerabilityRow) {
	existsVulnerabilitiesMap := make(map[string]xrayutils.VulnerabilityRow)
	vulnerabilitiesRows, err := xrayutils.CreateVulnerabilitiesRows(previousScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for _, vulnerability := range vulnerabilitiesRows {
		existsVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.CreateVulnerabilitiesRows(currentScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for _, vulnerability := range vulnerabilitiesRows {
		if _, exists := existsVulnerabilitiesMap[getUniqueID(vulnerability)]; !exists {
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return
}

func getUniqueID(vulnerability xrayutils.VulnerabilityRow) string {
	return vulnerability.ImpactedPackageName + vulnerability.ImpactedPackageVersion + vulnerability.IssueId
}

func createPullRequestMessage(vulnerabilitiesRows []xrayutils.VulnerabilityRow) string {
	if len(vulnerabilitiesRows) == 0 {
		return GetIconTag(NoVulnerabilityBannerSource)
	}
	tableHeder := "\n| SEVERITY | IMPACTED PACKAGE | IMPACTED PACKAGE  VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE\n" +
		":--: | -- | -- | -- | -- | :--: | --"
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += fmt.Sprintf("\n| %s | %s | %s | %s | %s | %s | %s ", GetIconTag(GetIconSource(vulnerability.Severity))+" "+vulnerability.Severity, vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion, vulnerability.FixedVersions, vulnerability.Components[0].Name, vulnerability.Components[0].Version, vulnerability.Cves[0].Id)
	}
	return GetIconTag(VulnerabilitiesBannerSource) + tableHeder + tableContent
}
