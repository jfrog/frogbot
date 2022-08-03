package commands

import (
	"fmt"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	clitool "github.com/urfave/cli/v2"
)

type FrogbotCommand interface {
	// Runs the command
	Run(params *utils.FrogbotParams, client vcsclient.VcsClient) error
}

func Exec(command FrogbotCommand, name string) error {
	// Get params and VCS client
	params, client, err := utils.GetParamsAndClient()
	if err != nil {
		return err
	}
	// Send usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(name, &params.Server, usageReportSent)
	// Invoke the command interface
	clientLog.Info(fmt.Sprintf("Running Frogbot %q command ", name))
	err = command.Run(params, client)
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
			Name:    "scan-pull-requests",
			Aliases: []string{"sprs"},
			Usage:   "Scans all the open pull requests in the repo with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(ScanAllPullRequestsCmd{}, ctx.Command.Name)
			},
			Flags: []clitool.Flag{},
		},
	}
}
