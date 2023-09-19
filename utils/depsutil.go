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

func resolveNpmDependencies(scanSetup *ScanDetails) (output []byte, err error) {
	npmCmd := npm.NewNpmCommand(scanSetup.InstallCommandArgs[0], false).SetServerDetails(scanSetup.ServerDetails)
	if err = npmCmd.PreparePrerequisites(scanSetup.DepsRepo); err != nil {
		return
	}
	if err = npmCmd.CreateTempNpmrc(); err != nil {
		return
	}
	defer func() {
		restoreNpmrc := npmCmd.RestoreNpmrcFunc()
		err = errors.Join(err, restoreNpmrc())
	}()
	output, err = exec.Command(coreutils.Npm.ToString(), scanSetup.InstallCommandArgs...).CombinedOutput()
	return
}

func resolveYarnDependencies(scanSetup *ScanDetails) (output []byte, err error) {
	currWd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	yarnExecPath, err := exec.LookPath("yarn")
	if err != nil {
		return
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
		return
	}

	registry, repoAuthIdent, err := yarn.GetYarnAuthDetails(scanSetup.ServerDetails, scanSetup.DepsRepo)
	if err != nil {
		err = yarn.RestoreConfigurationsAndError(nil, restoreYarnrcFunc, err)
		return
	}
	backupEnvMap, err := yarn.ModifyYarnConfigurations(yarnExecPath, registry, repoAuthIdent)
	if err != nil {
		err = yarn.RestoreConfigurationsAndError(backupEnvMap, restoreYarnrcFunc, err)
		return
	}
	defer func() {
		err = errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
	}()
	err = build.RunYarnCommand(yarnExecPath, currWd, scanSetup.InstallCommandArgs...)
	return
}

func resolveDotnetDependencies(scanSetup *ScanDetails) (output []byte, err error) {
	wd, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, fileutils.RemoveTempDir(wd))
	}()
	configFile, err := dotnet.InitNewConfig(wd, scanSetup.DepsRepo, scanSetup.ServerDetails, false)
	if err != nil {
		return
	}
	toolType := dotnetutils.ConvertNameToToolType(scanSetup.InstallCommandName)
	args := scanSetup.InstallCommandArgs
	args = append(args, toolType.GetTypeFlagPrefix()+"configfile", configFile.Name())
	return exec.Command(toolType.String(), args...).CombinedOutput()
}
