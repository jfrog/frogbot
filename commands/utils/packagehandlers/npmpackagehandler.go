package packagehandlers

import (
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/Masterminds/semver/v3"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"strconv"
)

const (
	packageLockName              = "package-lock.json"
	supportedPackageLockVersion  = 3
	lockFileVersionAttributeName = "lockfileVersion"
	indirectDependencyPath       = "packages.node_modules/%s.dependencies.%s"
)

type NpmPackageHandler struct {
	GenericPackageHandler
}

func (npm *NpmPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) (bool, error) {
	if fixVersionInfo.DirectDependency {
		return npm.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo)
	}
	err := npm.updateIndirectDependency(impactedPackage, fixVersionInfo)
	return err != nil, err
}

// updateIndirectDependency attempts changing the indirect dependency version
// The fix version should be compatible with the root package in order to fix the indirect package.
// If fails, log the error and return nil to avoid crashing the whole operation.
// See https://github.com/npm/node-semver#caret-ranges-123-025-004 for more info
func (npm *NpmPackageHandler) updateIndirectDependency(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (err error) {
	// TODO fix error handling
	var failConstraint bool
	parsedJson, err := loadPackageLockFile()
	if err != nil {
		log.Debug("Failed trying to load package-lock file: ", err)
		return nil
	}
	if failConstraint, err = modifyIndirectDependency(impactedPackage, fixVersionInfo, parsedJson); err != nil {
		log.Debug("Failed trying to modify package-lock file: ", err)
		return nil
	}
	if failConstraint {
		return fmt.Errorf("consrraint failed")
	}
	if err = saveModifiedFile(parsedJson); err != nil {
		log.Debug("Failed trying to save package-lock file: ", err)
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

func modifyIndirectDependency(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, parsedJson *gabs.Container) (constraint bool, err error) {
	directDependencyName := fixVersionInfo.Vulnerability.ImpactPaths[0][1].Name
	pathToModule := fmt.Sprintf(indirectDependencyPath, directDependencyName, impactedPackage)
	versionWithConstraint := parsedJson.Path(pathToModule).String()
	validFix, err := passesConstraint(versionWithConstraint, fixVersionInfo.FixVersion)
	if err != nil || !validFix {
		log.Info("Cannot update indirect dependency due compatibility constraint, skipping ...")
		return
	}
	_, err = parsedJson.SetP(fixVersionInfo.FixVersion, pathToModule)
	return true, nil
}

// Check that version is compatible with caret constraint
func passesConstraint(versionWithConstraint string, fixVersion string) (valid bool, err error) {
	_, err = strconv.Atoi(string(versionWithConstraint[0]))
	// No constraint, cant fix.
	if err != nil {
		return false, fmt.Errorf("no constraint")
	}
	a, err := semver.NewConstraint(versionWithConstraint)
	if err != nil {
		return
	}
	candidate, err := semver.NewVersion(fixVersion)
	if err != nil {
		return
	}
	return a.Check(candidate), nil
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
