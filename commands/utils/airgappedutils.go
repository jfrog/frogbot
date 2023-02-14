package utils

import (
	"github.com/jfrog/build-info-go/build"
	dotnetutils "github.com/jfrog/build-info-go/build/utils/dotnet"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/dotnet"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/npm"
	rtutils "github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/utils"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/yarn"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"os/exec"
	"path/filepath"
)

type resolveDependenciesFunc func(scanSetup *ScanSetup) ([]byte, error)

var MapTechToResolvingFunc = map[string]resolveDependenciesFunc{
	coreutils.Npm.ToString():    resolveNpmDependencies,
	coreutils.Yarn.ToString():   resolveYarnDependencies,
	coreutils.Dotnet.ToString(): resolveDotnetDependencies,
	coreutils.Nuget.ToString():  resolveDotnetDependencies,
}

func resolveNpmDependencies(scanSetup *ScanSetup) (output []byte, err error) {
	commonArgs := npm.CommonArgs{}
	commonArgs.SetServerDetails(scanSetup.ServerDetails)
	commonArgs.SetCmdName(scanSetup.InstallCommandArgs[0])
	if err = commonArgs.PreparePrerequisites(scanSetup.DepsResolutionRepo, true); err != nil {
		return nil, err
	}
	if err = commonArgs.CreateTempNpmrc(); err != nil {
		return nil, err
	}
	defer func() {
		restoreNpmrc := commonArgs.GetRestoreNpmrcFunc()
		if err == nil {
			err = restoreNpmrc()
		}
	}()
	return exec.Command(coreutils.Npm.ToString(), scanSetup.InstallCommandArgs...).CombinedOutput()
}

func resolveYarnDependencies(scanSetup *ScanSetup) (output []byte, err error) {
	currWd, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return nil, err
	}
	restoreYarnrcFunc, err := rtutils.BackupFile(filepath.Join(currWd, yarn.YarnrcFileName), filepath.Join(currWd, yarn.YarnrcBackupFileName))
	if err != nil {
		return nil, err
	}
	yarnExecPath, err := exec.LookPath("yarn")
	if err != nil {
		return nil, err
	}
	registry, repoAuthIdent, err := yarn.GetYarnAuthDetails(scanSetup.ServerDetails, scanSetup.DepsResolutionRepo)
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
	return nil, build.RunYarnCommand(yarnExecPath, currWd, scanSetup.InstallCommandArgs...)
}

func resolveDotnetDependencies(scanSetup *ScanSetup) (output []byte, err error) {
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
	configFile, err := dotnet.InitNewConfig(wd, scanSetup.DepsResolutionRepo, scanSetup.ServerDetails, false)
	if err != nil {
		return
	}
	toolType := dotnetutils.ConvertNameToToolType(scanSetup.InstallCommandName)
	args := scanSetup.InstallCommandArgs
	args = append(args, toolType.GetTypeFlagPrefix()+"configfile", configFile.Name())
	return exec.Command(toolType.String(), args...).CombinedOutput()
}
