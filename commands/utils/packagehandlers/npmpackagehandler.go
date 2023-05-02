package packagehandlers

import (
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"github.com/Masterminds/semver/v3"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
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

func (npm *NpmPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, extraArgs ...string) (shouldFix bool, err error) {
	if fixVersionInfo.DirectDependency {
		return npm.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo)
	}
	return npm.updateIndirectDependency(impactedPackage, fixVersionInfo)
}

// updateIndirectDependency attempts changing the indirect dependency version
// The fix version should be compatible with the root package in order to fix the indirect package.
// If fails, log the error and return nil to avoid crashing the whole operation.
// See https://github.com/npm/node-semver#caret-ranges-123-025-004 for more info
func (npm *NpmPackageHandler) updateIndirectDependency(impactedPackage string, fixVersionInfo *utils.FixVersionInfo) (shouldFix bool, err error) {
	parsedJson, err := loadPackageLockFile()
	if err != nil {
		log.Debug("Failed trying to load package-lock file: ", err)
		return
	}
	shouldFix, err = modifyIndirectDependency(impactedPackage, fixVersionInfo, parsedJson)
	if err != nil {
		log.Debug("Failed trying to modify package-lock file: ", err)
		return
	}
	if !shouldFix {
		log.Debug("Cannot update as fixed version does not match constraint")
		return false, nil
	}
	if err = saveModifiedFile(parsedJson); err != nil {
		log.Debug("Failed trying to save package-lock file: ", err)
		return
	}
	// Rewrites the package-lock file with updated hashes
	return true, runPackageMangerCommand(fixVersionInfo.PackageType.GetExecCommandName(), []string{"install"})
}

func saveModifiedFile(parsedJson *gabs.Container) error {
	bytes := parsedJson.Bytes()
	err := os.WriteFile(packageLockName, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func modifyIndirectDependency(impactedPackage string, fixVersionInfo *utils.FixVersionInfo, parsedJson *gabs.Container) (shouldFix bool, err error) {
	// Get value
	directDependencyName := fixVersionInfo.Vulnerability.ImpactPaths[0][1].Name
	pathToModule := fmt.Sprintf(indirectDependencyPath, directDependencyName, impactedPackage)
	versionWithConstraint := parsedJson.Path(pathToModule).String()
	// Check constraints
	validFix, err := passesConstraint(versionWithConstraint, fixVersionInfo.FixVersion)
	if err != nil || !validFix {
		log.Info("Cannot update indirect dependency due compatibility constraint, skipping ...")
		return false, nil
	}
	// Update fix version
	if _, err = parsedJson.SetP(fixVersionInfo.FixVersion, pathToModule); err != nil {
		return true, nil
	}
	return
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

// Check that version is compatible with semantic version constraint
func passesConstraint(versionWithConstraint string, fixVersion string) (valid bool, err error) {
	constraint, err := semver.NewConstraint(versionWithConstraint)
	if err != nil {
		return
	}
	candidate, err := semver.NewVersion(fixVersion)
	if err != nil {
		return
	}
	return constraint.Check(candidate), nil
}
