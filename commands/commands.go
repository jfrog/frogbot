package commands

import (
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/scanpullrequest"
	"github.com/jfrog/frogbot/commands/scanrepository"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clitool "github.com/urfave/cli/v2"
	"os"
)

type FrogbotCommand interface {
	// Run the command
	Run(config utils.RepoAggregator, client vcsclient.VcsClient) error
}

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanpullrequest.ScanPullRequestCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-repository",
			Aliases: []string{"cfpr", "create-fix-pull-requests"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanrepository.ScanRepositoryCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-all-pull-requests",
			Aliases: []string{"sprs", "scan-pull-requests"},
			Usage:   "Scans all the open pull requests within a single or multiple repositories with JFrog Xray for security vulnerabilities",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanpullrequest.ScanAllPullRequestsCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-multiple-repositories",
			Aliases: []string{"scan-and-fix-repos", "safr"},
			Usage:   "Scan single or multiple repositories and create pull requests with fixes if any security vulnerabilities are found",
			Action: func(ctx *clitool.Context) error {
				return Exec(&scanrepository.ScanMultipleRepositories{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
	}
}

func Exec(command FrogbotCommand, commandName string) (err error) {
	// Get frogbotDetails that contains the config, server, and VCS client
	log.Info("Frogbot version:", utils.FrogbotVersion)
	frogbotDetails, err := utils.GetFrogbotDetails()
	if err != nil {
		return err
	}

	// Build the server configuration file
	originalJfrogHomeDir, tempJFrogHomeDir, err := utils.BuildServerConfigFile(frogbotDetails.ServerDetails)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, os.Setenv(utils.JfrogHomeDirEnv, originalJfrogHomeDir), fileutils.RemoveTempDir(tempJFrogHomeDir))
	}()

	// Set releases remote repository env if needed
	previousReleasesRepoEnv := os.Getenv(coreutils.ReleasesRemoteEnv)
	if frogbotDetails.ReleasesRepo != "" {
		if err = os.Setenv(coreutils.ReleasesRemoteEnv, fmt.Sprintf("frogbot/%s", frogbotDetails.ReleasesRepo)); err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, os.Setenv(coreutils.ReleasesRemoteEnv, previousReleasesRepoEnv))
		}()
	}

	// Send a usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(commandName, frogbotDetails.ServerDetails, usageReportSent)

	// Invoke the command interface
	log.Info(fmt.Sprintf("Running Frogbot %q command", commandName))
	err = command.Run(frogbotDetails.Repositories, frogbotDetails.Client)

	// Wait for a signal, letting us know that the usage reporting is done.
	<-usageReportSent

	if err == nil {
		log.Info(fmt.Sprintf("Frogbot %q command finished successfully", commandName))
	}
	return err
}
