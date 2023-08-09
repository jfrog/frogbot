package packagehandlers

import (
	"bytes"
	"errors"
	biUtils "github.com/jfrog/build-info-go/build/utils"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"golang.org/x/exp/rand"
	"os/exec"
	"strconv"
	"time"
)

const (
	yarnV2Version          = "2.0.0"
	yarnV1PackageUpdateCmd = "upgrade"
	yarnV2PackageUpdateCmd = "up"
	modulesFolderFlag      = "--modules-folder=./"
)

type YarnPackageHandler struct {
	CommonPackageHandler
}

func (yarn *YarnPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return yarn.updateDirectDependency(vulnDetails)
	} else {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.SuggestedFixedVersion,
			ErrorType:    utils.IndirectDependencyFixNotSupported,
		}
	}
}

func (yarn *YarnPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails, extraArgs ...string) (err error) {
	clonedDirPath, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	yarnExecutablePath, err := biUtils.GetYarnExecutable()
	if err != nil {
		return
	}
	executableYarnVersion, err := biUtils.GetVersion(yarnExecutablePath, clonedDirPath)
	isV2AndAbove := version.NewVersion(executableYarnVersion).Compare(yarnV2Version) <= 0
	dirToDeleteName := ""
	if isV2AndAbove {
		vulnDetails.Technology.SetPackageInstallationCommand(yarnV2PackageUpdateCmd)
	} else {
		vulnDetails.Technology.SetPackageInstallationCommand(yarnV1PackageUpdateCmd)
		dirToDeleteName = getRandomToDeleteDirName()
		extraArgs = append(extraArgs, modulesFolderFlag+dirToDeleteName)
	}
	err = yarn.CommonPackageHandler.UpdateDependency(vulnDetails, extraArgs...)
	if err != nil {
		return
	}

	if !isV2AndAbove {
		return deleteNodeModulesDir(clonedDirPath, dirToDeleteName)
	}
	return
}

// deleteNodeModulesDir deletes a directory that contains node_modules that is automatically created when upgrading a package
// in yarn 1 ('yarn install' runs automatically when running 'yarn upgrade')
func deleteNodeModulesDir(clonedDirPath string, toDelete string) (err error) {
	command := exec.Command("rm", "-rf", clonedDirPath+"/"+toDelete)
	command.Dir = clonedDirPath
	errBuffer := bytes.NewBuffer([]byte{})
	command.Stderr = errBuffer
	err = command.Run()
	if err != nil {
		err = errors.New("removing " + toDelete + " directory after updating some package has failed:\n" + err.Error())
	}
	return
}

// getRandomToDeleteDirName returns a directory name that starts with 'to_delete' following a pseudo random number
// this directory is used to store node_modules created when upgrading packages in yarn 1 and needs to be deleted before pushed to VC
func getRandomToDeleteDirName() string {
	rand.Seed(uint64(time.Now().UnixNano()))
	randomNumberString := strconv.Itoa(int(rand.Int63n(1e9)))
	return "to_delete" + randomNumberString
}
