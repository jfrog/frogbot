package utils

import (
	"errors"
	"github.com/jfrog/build-info-go/build"
	biUtils "github.com/jfrog/build-info-go/build/utils"
	dotnetutils "github.com/jfrog/build-info-go/build/utils/dotnet"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/dotnet"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/npm"
	rtutils "github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/yarn"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os/exec"
	"path/filepath"
)

type resolveDependenciesFunc func(scanSetup *ScanDetails) ([]byte, error)

var MapTechToResolvingFunc = map[string]resolveDependenciesFunc{
	coreutils.Npm.ToString():    resolveNpmDependencies,
	coreutils.Yarn.ToString():   resolveYarnDependencies,
	coreutils.Dotnet.ToString(): resolveDotnetDependencies,
	coreutils.Nuget.ToString():  resolveDotnetDependencies,
}

const yarnV2Version = "2.0.0"

func resolveNpmDependencies(scanDetails *ScanDetails) (output []byte, err error) {
	npmCmd := npm.NewNpmCommand(scanDetails.project.InstallCommandArgs[0], false).SetServerDetails(&scanDetails.serverDetails)
	if err = npmCmd.PreparePrerequisites(scanDetails.project.DepsRepo); err != nil {
		return nil, err
	}
	if err = npmCmd.CreateTempNpmrc(); err != nil {
		return nil, err
	}
	defer func() {
		restoreNpmrc := npmCmd.RestoreNpmrcFunc()
		if err == nil {
			err = restoreNpmrc()
		}
	}()
	return exec.Command(coreutils.Npm.ToString(), scanDetails.project.InstallCommandArgs...).CombinedOutput()
}

func resolveYarnDependencies(scanDetails *ScanDetails) (output []byte, err error) {
	currWd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return nil, err
	}
	yarnExecPath, err := exec.LookPath("yarn")
	if err != nil {
		return nil, err
	}

	executableYarnVersion, err := biUtils.GetVersion(yarnExecPath, currWd)
	if err != nil {
		return
	}

	// Checking if the current yarn version is Yarn V1, and if so - abort. Resolving dependencies is currently not supported for Yarn V1
	if version.NewVersion(executableYarnVersion).Compare(yarnV2Version) > 0 {
		err = errors.New("resolving yarn dependencies is currently not supported for Yarn V1")
		return
	}

	restoreYarnrcFunc, err := rtutils.BackupFile(filepath.Join(currWd, yarn.YarnrcFileName), yarn.YarnrcBackupFileName)
	if err != nil {
		return nil, err
	}

	registry, repoAuthIdent, err := yarn.GetYarnAuthDetails(&scanDetails.serverDetails, scanDetails.project.DepsRepo)
	if err != nil {
		return nil, yarn.RestoreConfigurationsAndError(nil, restoreYarnrcFunc, err)
	}
	backupEnvMap, err := yarn.ModifyYarnConfigurations(yarnExecPath, registry, repoAuthIdent)
	if err != nil {
		return nil, yarn.RestoreConfigurationsAndError(backupEnvMap, restoreYarnrcFunc, err)
	}
	defer func() {
		e := yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc)
		if err == nil {
			err = e
		}
	}()
	return nil, build.RunYarnCommand(yarnExecPath, currWd, scanDetails.project.InstallCommandArgs...)
}

func resolveDotnetDependencies(scanDetails *ScanDetails) (output []byte, err error) {
	wd, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	defer func() {
		e := fileutils.RemoveTempDir(wd)
		if err == nil {
			err = e
		}
	}()
	configFile, err := dotnet.InitNewConfig(wd, scanDetails.project.DepsRepo, &scanDetails.serverDetails, false)
	if err != nil {
		return
	}
	toolType := dotnetutils.ConvertNameToToolType(scanDetails.project.InstallCommandName)
	args := scanDetails.project.InstallCommandArgs
	args = append(args, toolType.GetTypeFlagPrefix()+"configfile", configFile.Name())
	return exec.Command(toolType.String(), args...).CombinedOutput()
}
