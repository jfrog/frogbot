package commands

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clitool "github.com/urfave/cli/v2"
)

type FrogbotCommand interface {
	// Run the command
	Run(config utils.RepoAggregator, client vcsclient.VcsClient) error
}

func Exec(command FrogbotCommand, name string) error {
	// Get frogbotUtils the contains the config, server and VCS client
	log.Info("Frogbot version:", utils.FrogbotVersion)
	frogbotUtils, err := utils.GetFrogbotUtils()
	if err != nil {
		return err
	}
	// Download extractors if the jfrog releases repo environment variable is set
	releasesRepo := frogbotUtils.Repositories[0].JfrogReleasesRepo
	if err = utils.DownloadExtractorsFromRemoteIfNeeded(frogbotUtils.ServerDetails, "", releasesRepo); err != nil {
		return err
	}
	// Send a usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(name, frogbotUtils.ServerDetails, usageReportSent)
	// Invoke the command interface
	log.Info(fmt.Sprintf("Running Frogbot %q command", name))
	err = command.Run(frogbotUtils.Repositories, frogbotUtils.Client)
	// Wait for a signal, letting us know that the usage reporting is done.
	<-usageReportSent
	if err == nil {
		log.Info(fmt.Sprintf("Frogbot %q command finished successfully ", name))
	}
	return err
}

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(&ScanPullRequestCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "create-fix-pull-requests",
			Aliases: []string{"cfpr"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action: func(ctx *clitool.Context) error {
				return Exec(&CreateFixPullRequestsCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-pull-requests",
			Aliases: []string{"sprs"},
			Usage:   "Scans all the open pull requests within a single or multiple repositories with JFrog Xray for security vulnerabilities",
			Action: func(ctx *clitool.Context) error {
				return Exec(&ScanAllPullRequestsCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-and-fix-repos",
			Aliases: []string{"safr"},
			Usage:   "Scan single or multiple repositories and create pull requests with fixes if any security vulnerabilities are found",
			Action: func(ctx *clitool.Context) error {
				return Exec(&ScanAndFixRepositories{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
	}
}
