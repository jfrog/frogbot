package main

import (
	"errors"
	"os"

	"github.com/jfrog/frogbot/commands"
	"github.com/jfrog/frogbot/commands/utils"
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
		ExitErrHandler: func(context *clitool.Context, err error) {
			if errors.Is(err, utils.ErrLabelCreated) || errors.Is(err, utils.ErrUnlabel) {
				clientLog.Info("Scan wasn't triggered: " + err.Error())
				os.Exit(0)
			}
		},
	}

	err := app.Run(os.Args)
	return err
}

func getCommands() []*clitool.Command {
	return []*clitool.Command{
		{
			Name:    "scan-pull-request",
			Aliases: []string{"spr"},
			Hidden:  true,
			Action:  commands.ScanPullRequest,
		},
	}
}
