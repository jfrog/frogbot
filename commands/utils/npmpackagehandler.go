package utils

type NpmPackageHandler struct {
	GenericPackageHandler
}

func (npm *NpmPackageHandler) UpdatePackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	if fixVersionInfo.IsDirectDependency {
		return npm.GenericPackageHandler.UpdatePackage(impactedPackage, fixVersionInfo)
	}
	// Indirect dependencies are install as dev and then deleted
	// This effect only the .lock file
	if err := npm.GenericPackageHandler.UpdatePackage(impactedPackage, fixVersionInfo, "-D"); err != nil {
		return err
	}
	return runPackageMangerCommand("npm", []string{"uninstall", impactedPackage})
}
