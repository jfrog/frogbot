package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

// PackageHandler interface to hold operations on packages
type PackageHandler interface {
	UpdateDependency(details *utils.VulnerabilityDetails) error
	SetCommonParams(serverDetails *config.ServerDetails, depsRepo string)
}

func GetCompatiblePackageHandler(vulnDetails *utils.VulnerabilityDetails, details *utils.ScanDetails) (handler PackageHandler) {
	switch vulnDetails.Technology {
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
		handler = NewMavenPackageHandler(details)
	case coreutils.Nuget:
		handler = &NugetPackageHandler{}
	case coreutils.Gradle:
		handler = &GradlePackageHandler{}
	default:
		handler = &UnsupportedPackageHandler{}
	}
	handler.SetCommonParams(details.ServerDetails, details.DepsRepo)
	return
}

type CommonPackageHandler struct {
	serverDetails *config.ServerDetails
	depsRepo      string
}

// UpdateDependency updates the impacted package to the fixed version
func (cph *CommonPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails, installationCommand string, extraArgs ...string) (err error) {
	// Lower the package name to avoid duplicates
	impactedPackage := strings.ToLower(vulnDetails.ImpactedDependencyName)
	commandArgs := []string{installationCommand}
	commandArgs = append(commandArgs, extraArgs...)
	versionOperator := vulnDetails.Technology.GetPackageVersionOperator()
	fixedPackageArgs := getFixedPackage(impactedPackage, versionOperator, vulnDetails.SuggestedFixedVersion)
	commandArgs = append(commandArgs, fixedPackageArgs...)
	return runPackageMangerCommand(vulnDetails.Technology.GetExecCommandName(), vulnDetails.Technology.String(), commandArgs)
}

func (cph *CommonPackageHandler) SetCommonParams(serverDetails *config.ServerDetails, depsRepo string) {
	cph.serverDetails = serverDetails
	cph.depsRepo = depsRepo
}

func runPackageMangerCommand(commandName string, techName string, commandArgs []string) error {
	fullCommand := commandName + " " + strings.Join(commandArgs, " ")
	log.Debug(fmt.Sprintf("Running '%s'", fullCommand))
	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	output, err := exec.Command(commandName, commandArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update %s dependency: '%s' command failed: %s\n%s", techName, fullCommand, err.Error(), output)
	}
	return nil
}

// Returns the updated package and version as it should be run in the update command:
// If the package manager expects a single string (example: <packName>@<version>) it returns []string{<packName>@<version>}
// If the command args suppose to be seperated by spaces (example: <packName> -v <version>) it returns []string{<packName>, "-v", <version>}
func getFixedPackage(impactedPackage string, versionOperator string, suggestedFixedVersion string) (fixedPackageArgs []string) {
	fixedPackageString := strings.TrimSpace(impactedPackage) + versionOperator + strings.TrimSpace(suggestedFixedVersion)
	fixedPackageArgs = strings.Split(fixedPackageString, " ")
	return
}
