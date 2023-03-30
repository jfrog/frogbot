package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

// PackageUpdater
type GenericPackageHandler struct {
	FixVersionInfo *FixVersionInfo
}

func (g *GenericPackageHandler) UpdatePackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	commandArgs := []string{fixVersionInfo.PackageType.GetPackageInstallOperator()}
	for _, arg := range extraArgs {
		commandArgs = append(commandArgs, arg)
	}
	operator := fixVersionInfo.PackageType.GetPackageOperator()
	fixedPackage := impactedPackage + operator + fixVersionInfo.FixVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(fixVersionInfo.PackageType.GetExecCommandName(), commandArgs)
}

func runPackageMangerCommand(commandName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("%s command failed: %s\n%s", fullCommand, err.Error(), output)
	}
	return nil
}
