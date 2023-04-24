package packagehandlers

import (
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
)

const (
	packageLockName              = "package-lock.json"
	supportedPackageLockVersion  = 3
	lockFileVersionAttributeName = "lockfileVersion"
)

type NpmPackageHandler struct {
	GenericPackageHandler
}

func (npm *NpmPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) error {
	if fixVersionInfo.DirectDependency {
		return npm.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo)
	}
	return npm.updateIndirectDependency(impactedPackage, fixVersionInfo)
}

// updateIndirectDependency attempts changing the indirect dependency version
// If fails, log the error and return nil to avoid crashing the whole operation.
func (npm *NpmPackageHandler) updateIndirectDependency(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (err error) {
	parsedJson, err := loadPackageLockFile()
	if err != nil {
		log.Error("Failed trying to load package-lock file: ", err)
		return nil
	}
	if err = modifyIndirectDependency(impactedPackage, fixVersionInfo, parsedJson, err); err != nil {
		log.Error("Failed trying to modify package-lock file: ", err)
		return nil
	}
	if err = saveModifiedFile(parsedJson); err != nil {
		log.Error("Failed trying to save package-lock file: ", err)
		return nil
	}
	// Rewrites the package-lock file with updated hashes
	return runPackageMangerCommand(fixVersionInfo.PackageType.GetExecCommandName(), []string{"install"})
}

func saveModifiedFile(parsedJson *gabs.Container) error {
	bytes := parsedJson.Bytes()
	err := os.WriteFile(packageLockName, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func modifyIndirectDependency(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, parsedJson *gabs.Container, err error) error {
	directDependencyName := fixVersionInfo.Vulnerability.ImpactPaths[0][1].Name
	pathToModule := fmt.Sprintf("packages.node_modules/%s.dependencies.%s", directDependencyName, impactedPackage)
	// TODO check constraint!
	_, err = parsedJson.SetP(fixVersionInfo.FixVersion, pathToModule)
	if err != nil {
		return err
	}
	return nil
}

func loadPackageLockFile() (*gabs.Container, error) {
	packageLockFile, err := os.ReadFile(packageLockName)
	if err != nil {
		return nil, err
	}
	container, err := gabs.ParseJSON(packageLockFile)
	if err != nil {
		return nil, err
	}
	packageLockVersion := container.Path(lockFileVersionAttributeName).Data().(float64)
	if packageLockVersion < supportedPackageLockVersion {
		return nil, fmt.Errorf("unsupported version of package lock file %f", packageLockVersion)
	}
	return container, nil
}
