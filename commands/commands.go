package commands

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	clitool "github.com/urfave/cli/v2"
)

type FrogbotCommand interface {
	// Run the command
	Run(config utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error
}

func Exec(command FrogbotCommand, name string) error {
	// Get config, server and VCS client
	configAggregator, server, client, err := utils.GetParamsAndClient()
	if err != nil {
		return err
	}
	// Send usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(name, server, usageReportSent)
	// Invoke the command interface
	clientLog.Info(fmt.Sprintf("Running Frogbot %q command ", name))
	err = command.Run(configAggregator, client)
	// Waits for the signal from the report usage to be done.
	<-usageReportSent
	if err == nil {
		clientLog.Info(fmt.Sprintf("Frogbot %q command finished successfully ", name))
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
				return Exec(ScanPullRequestCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "create-fix-pull-requests",
			Aliases: []string{"cfpr"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action: func(ctx *clitool.Context) error {
				return Exec(CreateFixPullRequestsCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-repos",
			Aliases: []string{"sprs", "scan-pull-requests", "scr"},
			Usage:   "Scans all the open pull requests in single or multiple repositories with JFrog Xray for security vulnerabilities",
			Action: func(ctx *clitool.Context) error {
				return Exec(ScanRepositories{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-and-fix-repos",
			Aliases: []string{"safr"},
			Usage:   "Scan single or multiple repositories and create pull requests with fixes if any security vulnerabilities found",
			Action: func(ctx *clitool.Context) error {
				return Exec(ScanAndFixRepositories{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
	}
}
