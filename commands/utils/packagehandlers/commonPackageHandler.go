package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

// PackageHandler interface to hold operations on packages
type PackageHandler interface {
	UpdateDependency(details *utils.FixDetails) error
}

func GetCompatiblePackageHandler(fixVersionInfo *utils.FixDetails, details *utils.ScanDetails, mavenPropertyMap *map[string][]string) (handler PackageHandler, err error) {
	switch fixVersionInfo.PackageType {
	case coreutils.Go:
		handler = &GoPackageHandler{}
	case coreutils.Poetry:
		handler = &PythonPackageHandler{}
	case coreutils.Pipenv:
		handler = &PythonPackageHandler{}
	case coreutils.Npm:
		handler = &NpmPackageHandler{}
	case coreutils.Yarn:
		handler = &YarnPackageHandler{}
	case coreutils.Pip:
		handler = &PythonPackageHandler{pipRequirementsFile: details.PipRequirementsFile}
	case coreutils.Maven:
		handler = &MavenPackageHandler{mavenDepToPropertyMap: *mavenPropertyMap}
	default:
		err = fmt.Errorf("incompatiable package handler: %s", fixVersionInfo.PackageType)
		return
	}
	return
}

type CommonPackageHandler struct{}

// UpdateDependency updates the impacted package to the fixed version
func (cph *CommonPackageHandler) UpdateDependency(fixDetails *utils.FixDetails, extraArgs ...string) (err error) {
	// Lower the package name to avoid duplicates
	impactedPackage := strings.ToLower(fixDetails.ImpactedDependency)
	commandArgs := []string{fixDetails.PackageType.GetPackageInstallOperator()}
	commandArgs = append(commandArgs, extraArgs...)
	operator := fixDetails.PackageType.GetPackageOperator()
	fixedPackage := impactedPackage + operator + fixDetails.FixVersion
	commandArgs = append(commandArgs, fixedPackage)
	return runPackageMangerCommand(fixDetails.PackageType.GetExecCommandName(), commandArgs)
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
