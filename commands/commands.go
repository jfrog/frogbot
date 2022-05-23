package commands

import clitool "github.com/urfave/cli/v2"

func GetCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action:  ScanPullRequest,
			Flags:   []clitool.Flag{},
		},
		{
			Name:    "create-fix-pull-requests",
			Aliases: []string{"cfpr"},
			Usage:   "Scan the current branch and create pull requests with fixes if needed",
			Action:  CreateFixPullRequests,
			Flags:   []clitool.Flag{},
		},
		{
			Name:    "scan-pull-requests",
			Aliases: []string{"sprs"},
			Usage:   "Scans all the open pull requests in the repo with JFrog Xray for security vulnerabilities.",
			Action:  ScanPullRequests,
			Flags:   []clitool.Flag{},
		},
	}
}
