package main

import (
	"os"

	"github.com/jfrog/frogbot/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/log"
	clitool "github.com/urfave/cli/v2"
)

var frogbotVersion = "0.0.0"

func main() {
	log.SetDefaultLogger()
	coreutils.ExitOnErr(ExecMain())
}

func ExecMain() error {
	app := clitool.App{
		Name:     "Frogbot",
		Usage:    "See https://github.com/jfrog/frogbot for usage instructions.",
		Commands: commands.GetCommands(),
		Version:  frogbotVersion,
	}

	err := app.Run(os.Args)
	return err
}
