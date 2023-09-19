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

type resolveDependenciesFunc func(scanSetup *ScanDetails) error

var MapTechToResolvingFunc = map[string]resolveDependenciesFunc{
	coreutils.Npm.String():    resolveNpmDependencies,
	coreutils.Yarn.String():   resolveYarnDependencies,
	coreutils.Dotnet.String(): resolveDotnetDependencies,
	coreutils.Nuget.String():  resolveDotnetDependencies,
}

const yarnV2Version = "2.0.0"

func resolveNpmDependencies(scanSetup *ScanDetails) error {
	return npm.NewNpmCommand(scanSetup.InstallCommandArgs[0], false).
		SetServerDetails(scanSetup.ServerDetails).
		SetRepo(scanSetup.DepsRepo).
		Run()
}

func resolveYarnDependencies(scanSetup *ScanDetails) (err error) {
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
		err = errors.Join(err, restoreYarnrcFunc())
		return
	}
	backupEnvMap, err := yarn.ModifyYarnConfigurations(yarnExecPath, registry, repoAuthIdent)
	if err != nil {
		if len(backupEnvMap) > 0 {
			err = errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
		} else {
			err = errors.Join(err, restoreYarnrcFunc())
		}
		return
	}
	defer func() {
		err = errors.Join(err, yarn.RestoreConfigurationsFromBackup(backupEnvMap, restoreYarnrcFunc))
	}()
	err = build.RunYarnCommand(yarnExecPath, currWd, scanSetup.InstallCommandArgs...)
	return
}

func resolveDotnetDependencies(scanSetup *ScanDetails) (err error) {
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
	//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
	_, err = exec.Command(toolType.String(), args...).CombinedOutput()
	return
}
