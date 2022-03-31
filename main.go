package main

import (
	"os"

	"github.com/jfrog/frogbot/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/log"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	clitool "github.com/urfave/cli/v2"
)

var frogbotVersion = "0.0.0"

func main() {
	log.SetDefaultLogger()
	err := execMain()
	if cleanupErr := fileutils.CleanOldDirs(); cleanupErr != nil {
		clientLog.Warn(cleanupErr)
	}
	coreutils.ExitOnErr(err)
}

func execMain() error {
	app := clitool.App{
		Name:     "Frogbot",
		Usage:    "See https://github.com/jfrog/frogbot for usage instructions.",
		Commands: getCommands(),
		Version:  frogbotVersion,
	}

	err := app.Run(os.Args)
	return err
}

func getCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Usage:   "Scans a pull request with JFrog Xray for security vulnerabilities.",
			Action:  commands.ScanPullRequest,
			Flags:   commands.GetScanPullRequestFlags(),
		},
	}
}
