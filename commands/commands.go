package commands

import (
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	clitool "github.com/urfave/cli/v2"
)

type FrogbotCommand interface {
	// Runs the command
	Run(params *utils.FrogbotParams, client vcsclient.VcsClient) error
	// The command name for the usage report.
	Name() string
}

func Exec(command FrogbotCommand) error {
	// Get params and VCS client
	params, client, err := utils.GetParamsAndClient()
	if err != nil {
		return err
	}
	// Send usage report
	usageReportSent := make(chan error)
	go utils.ReportUsage(command.Name(), &params.Server, usageReportSent)
	// Invoke the command interface
	err = command.Run(params, client)
	// Waits for the signal from the report usage to be done.
	<-usageReportSent
	return err
}

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(ScanPullRequestCmd{})
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "create-fix-pull-requests",
			Aliases: []string{"cfpr"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action: func(ctx *clitool.Context) error {
				return Exec(CreatePullRequestCmd{})
			},
			Flags: []clitool.Flag{},
		},
		{
			Name:    "scan-pull-requests",
			Aliases: []string{"sprs"},
			Usage:   "Scans all the open pull requests in the repo with JFrog Xray for security vulnerabilities.",
			Action: func(ctx *clitool.Context) error {
				return Exec(ScanPullRequestsCmd{})
			},
			Flags: []clitool.Flag{},
		},
	}
}
