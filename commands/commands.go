package commands

import clitool "github.com/urfave/cli/v2"

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action:  ScanPullRequest,
			Flags:   GetScanPullRequestFlags(),
		},
	}
}
