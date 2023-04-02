package packagehandlers

import (
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os/exec"
	"strings"
)

// FixVersionInfo Basic struct used to hold needed information about version fixing
type FixVersionInfo struct {
	FixVersion         string
	PackageType        coreutils.Technology
	IsDirectDependency bool
}

func NewFixVersionInfo(newFixVersion string, packageType coreutils.Technology, isDirectDependency bool) *FixVersionInfo {
	return &FixVersionInfo{newFixVersion, packageType, isDirectDependency}
}

func (fvi *FixVersionInfo) UpdateFixVersion(newFixVersion string) {
	// Update fvi.FixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if fvi.FixVersion == "" || version.NewVersion(fvi.FixVersion).Compare(newFixVersion) > 0 {
		fvi.FixVersion = newFixVersion
	}
}

// PackageUpdater Interface to hold operations on packages
type PackageUpdater interface {
	UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error
}

func GetCompatiblePackageHandler(fixVersionInfo *FixVersionInfo, pipfilePath *utils.ScanDetails, mavenPropertyMap *map[string][]string) PackageUpdater {
	switch fixVersionInfo.PackageType {
	case coreutils.Go:
		return &GoPackageHandler{}
	case coreutils.Maven:
		return &MavenPackageHandler{MavenDepToPropertyMap: *mavenPropertyMap}
	case coreutils.Poetry:
		return &PythonPackageHandler{}
	case coreutils.Pip:
		return &PythonPackageHandler{PipRequirementsFile: pipfilePath.PipRequirementsFile}
	case coreutils.Npm:
		return &NpmPackageHandler{}
	default:
		return &GenericPackageHandler{FixVersionInfo: fixVersionInfo}
	}
}

type GenericPackageHandler struct {
	FixVersionInfo *FixVersionInfo
}

// UpdateImpactedPackage installs new version of the impacted package to the fixed version
func (g *GenericPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
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
