package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/agnivade/levenshtein"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/log"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/urfave/cli"
)

const commandHelpTemplate string = `{{.HelpName}}{{if .UsageText}}
Arguments:
{{.UsageText}}
{{end}}{{if .VisibleFlags}}
Options:
	{{range .VisibleFlags}}{{.}}
	{{end}}{{end}}{{if .ArgsUsage}}
Environment Variables:
{{.ArgsUsage}}{{end}}

`

const subcommandHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
	{{if .Usage}}{{.Usage}}{{ "\n\t" }}{{end}}{{.HelpName}} command{{if .VisibleFlags}} [command options]{{end}} [arguments...]

COMMANDS:
   {{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
   {{end}}{{if .VisibleFlags}}{{if .ArgsUsage}}
Arguments:
{{.ArgsUsage}}{{ "\n" }}{{end}}
OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
{{end}}
`

func main() {
	log.SetDefaultLogger()
	err := execMain()
	if cleanupErr := fileutils.CleanOldDirs(); cleanupErr != nil {
		clientLog.Warn(cleanupErr)
	}
	coreutils.ExitOnErr(err)
}

func execMain() error {

	app := cli.NewApp()
	app.Name = "frogbot"
	app.Usage = "See https://github.com/jfrog/frogbot for usage instructions."
	app.Version = "0.0.0"
	args := os.Args
	app.EnableBashCompletion = true
	app.Commands = getCommands()
	cli.CommandHelpTemplate = commandHelpTemplate
	cli.AppHelpTemplate = getAppHelpTemplate()
	cli.SubcommandHelpTemplate = subcommandHelpTemplate
	app.CommandNotFound = func(c *cli.Context, command string) {
		fmt.Fprintf(c.App.Writer, "'"+c.App.Name+" "+command+"' is not a jf command. See --help\n")
		if bestSimilarity := searchSimilarCmds(c.App.Commands, command); len(bestSimilarity) > 0 {
			text := "The most similar "
			if len(bestSimilarity) == 1 {
				text += "command is:\n\tjf " + bestSimilarity[0]
			} else {
				sort.Strings(bestSimilarity)
				text += "commands are:\n\tjf " + strings.Join(bestSimilarity, "\n\tjf ")
			}
			fmt.Fprintln(c.App.Writer, text)
		}
		os.Exit(1)
	}
	err := app.Run(args)
	return err
}

// Detects typos and can identify one or more valid commands similar to the error command.
// In Addition, if a subcommand is found with exact match, preferred it over similar commands, for example:
// "jf bp" -> return "jf rt bp"
func searchSimilarCmds(cmds []cli.Command, toCompare string) (bestSimilarity []string) {
	// Set min diff between two commands.
	minDistance := 2
	for _, cmd := range cmds {
		// Check if we have an exact match with the next level.
		for _, subCmd := range cmd.Subcommands {
			for _, subCmdName := range subCmd.Names() {
				// Found exact match, return it.
				distance := levenshtein.ComputeDistance(subCmdName, toCompare)
				if distance == 0 {
					return []string{cmd.Name + " " + subCmdName}
				}
			}
		}
		// Search similar commands with max diff of 'minDistance'.
		for _, cmdName := range cmd.Names() {
			distance := levenshtein.ComputeDistance(cmdName, toCompare)
			if distance == minDistance {
				// In the case of an alias, we don't want to show the full command name, but the alias.
				// Therefore, we trim the end of the full name and concat the actual matched (alias/full command name)
				bestSimilarity = append(bestSimilarity, strings.Replace(cmd.FullName(), cmd.Name, cmdName, 1))
			}
			if distance < minDistance {
				// Found a cmd with a smaller distance.
				minDistance = distance
				bestSimilarity = []string{strings.Replace(cmd.FullName(), cmd.Name, cmdName, 1)}
			}
		}
	}
	return
}

const otherCategory = "Other"

func getCommands() []cli.Command {
	return []cli.Command{
		{
			Name:     "comment-pr",
			HideHelp: true,
			Hidden:   true,
			Category: otherCategory,
			Action:   commentPullRequest,
		},
	}
}

func getAppHelpTemplate() string {
	return `NAME:
   ` + coreutils.GetCliExecutableName() + ` - {{.Usage}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} [arguments...]{{end}}
   {{if .Version}}
VERSION:
   {{.Version}}
   {{end}}{{if len .Authors}}
AUTHOR(S):
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .VisibleCommands}}
COMMANDS:{{range .VisibleCategories}}{{if .Name}}

   {{.Name}}:{{end}}{{range .VisibleCommands}}
     {{join .Names ", "}}{{ "\t" }}{{if .Description}}{{.Description}}{{else}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{if .VisibleFlags}}

GLOBAL OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
{{end}}
`
}

func commentPullRequest(c *cli.Context) error {
	server, repoOwner, token, repo, targetBranch, pullRequestID, err := extractParamsFromEnv()
	if err != nil {
		return err
	}
	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).Token(token).Build()
	if err != nil {
		return err
	}

	// Audit PR code
	// TODO - fill contex according to env/flags
	xrayScanParams := services.XrayGraphScanParams{}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	currentScan, err := runAudit(xrayScanParams, &server, wd)
	// Audit target code
	previousScan, err := auditTarget(client, xrayScanParams, &server, repoOwner, repo, targetBranch)
	if err != nil {
		return err
	}
	// Get only the new issues added by this PR
	violations := getNewViolations(previousScan[0], currentScan[0]) // TODO - handle array of scan results!
	// Comment frogbot message on the PR
	message := createPullRequestMessage(violations)
	return client.AddPullRequestComment(context.Background(), repoOwner, repo, message, pullRequestID)

}

func extractParamsFromEnv() (server coreconfig.ServerDetails, repoOwner, token, repo, targetBranch string, pullRequestID int, err error) {
	// Constants
	jfrogUser := "FROGBOT_JF_USER"
	jfrogUrl := "FROGBOT_JF_URL"
	jfrogPassword := "FROGBOT_JF_PASSWORD"
	jfrogToken := "FROGBOT_JF_TOKEN"
	gitRepoOwner := "FROGBOT_GIT_OWNER"
	gitToken := "FROGBOT_GIT_TOKEN"
	branch := "FROGBOT_BRANCH"
	prID := "FROGBOT_PR"

	url, exists := os.LookupEnv(jfrogUrl)
	if !exists {
		err = fmt.Errorf("%s is missing", jfrogUrl)
		return
	}
	server.Url = url
	password, passwordExists := os.LookupEnv(jfrogPassword)
	user, userExists := os.LookupEnv(jfrogUser)
	if passwordExists && userExists {
		server.User = user
		server.Password = password
	} else if accessToken, exists := os.LookupEnv(jfrogToken); exists {
		server.AccessToken = accessToken
	} else {
		err = fmt.Errorf("%s and %s or %s are missing", jfrogUser, jfrogPassword, jfrogToken)
		return
	}
	if repoOwner, exists = os.LookupEnv(gitRepoOwner); !exists {
		err = fmt.Errorf("%s is missing", gitRepoOwner)
		return
	}
	if token, exists = os.LookupEnv(gitToken); !exists {
		err = fmt.Errorf("%s is missing", gitToken)
		return
	}
	if targetBranch, exists = os.LookupEnv(branch); !exists {
		err = fmt.Errorf("%s is missing", branch)
		return
	}
	pullRequestIDString, exists := os.LookupEnv(prID)
	if !exists {
		err = fmt.Errorf("%s is missing", prID)
		return
	}
	pullRequestID, err = strconv.Atoi(pullRequestIDString)
	if err != nil {
		return
	}
	return
}

func runAudit(xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails, workDir string) (res []services.ScanResponse, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	err = os.Chdir(workDir)
	if err != nil {
		return
	}
	defer func(originDir string) {
		e := os.Chdir(originDir)
		if err == nil {
			err = e
		}
	}(wd)
	// TODO - handle audit params better
	return audit.GenericAudit(xrayScanParams, server, false, false, false, []string{})
}

func auditTarget(client vcsclient.VcsClient, xrayScanParams services.XrayGraphScanParams, server *coreconfig.ServerDetails, owner, repo, branch string) (res []services.ScanResponse, err error) {
	// First download the target repo to temp dir
	tempWorkdir, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	defer fileutils.RemoveTempDir(tempWorkdir)
	err = client.DownloadRepository(context.Background(), owner, repo, branch, tempWorkdir)
	return runAudit(xrayScanParams, server, tempWorkdir)
}

func getNewViolations(previousScan, currentScan services.ScanResponse) (newViolationsRows []xrayutils.VulnerabilityRow) {
	existsViolationsMap := make(map[string]xrayutils.VulnerabilityRow)
	violationsRows, _, err := xrayutils.CreateViolationsRows(previousScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		existsViolationsMap[GetUniqueID(violation)] = violation
	}
	violationsRows, _, err = xrayutils.CreateViolationsRows(currentScan.Violations, false, false)
	if err != nil {
		return
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[GetUniqueID(violation)]; !exists {
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
		existsVulnerabilitiesMap[GetUniqueID(vulnerability)] = vulnerability
	}
	vulnerabilitiesRows, err = xrayutils.CreateVulnerabilitiesRows(currentScan.Vulnerabilities, false, false)
	if err != nil {
		return
	}
	for _, vulnerability := range vulnerabilitiesRows {
		if _, exists := existsVulnerabilitiesMap[GetUniqueID(vulnerability)]; !exists {
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return

}

func GetUniqueID(vulnerability xrayutils.VulnerabilityRow) string {
	return vulnerability.IssueId + vulnerability.Components[0].Name

}

func createPullRequestMessage(vulnerabilitiesRows []xrayutils.VulnerabilityRow) string {
	// DUMMY Images for tests!
	noVulnerabilityImageTag := `<img  src="https://speedmedia.jfrog.com/08612fe1-9391-4cf3-ac1a-6dd49c36b276/https://media.jfrog.com/wp-content/uploads/2021/12/29113553/jfrog-logo-2022.svg/mxw_96,f_auto">`
	vulnerabilityImageTag := `<img  src="https://speedmedia.jfrog.com/08612fe1-9391-4cf3-ac1a-6dd49c36b276/https://media.jfrog.com/wp-content/uploads/2019/11/20130210/Blog-post-GoCenter-04.jpg/mxw_1024,f_auto">`
	//

	if len(vulnerabilitiesRows) == 0 {
		return noVulnerabilityImageTag
	}
	tableHeder := `| SEVERITY | IMPACTED PACKAGE | IMPACTED PACKAGE  VERSION | FIXED VERSIONS | COMPONENT | COMPONENT VERSION | CVE |
	| --- | --- |  --- | --- |  --- | --- | --- | --- |`
	tableContent := `

	
	`
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n", vulnerability.Severity, vulnerability.ImpactedPackageName,
			vulnerability.ImpactedPackageVersion, vulnerability.FixedVersions, vulnerability.Components[0].Name, vulnerability.Components[0].Version, vulnerability.Cves[0].Id)
	}
	return vulnerabilityImageTag + tableHeder + tableContent //`| High | github.com/mholt/archiver/v3 | v3.5.1-0.20210618180617-81fac4ba96e4 | Go | | github.com/jfrog/jfrog-client-go github.com/jfrog/jfrog-cli-core/v2 | v1.8.0 |`
}

func commentPullRequestGithub(client vcsclient.VcsClient, owner, repository, content string) error {

	return client.AddPullRequestComment(context.Background(), owner, repository, content, 1)
}
