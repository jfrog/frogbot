package packagehandlers

type NpmPackageHandler struct {
	GenericPackageHandler
}

func (npm *NpmPackageHandler) UpdateImpactedPackage(impactedPackage string, fixVersionInfo *FixVersionInfo, extraArgs ...string) error {
	if fixVersionInfo.IsDirectDependency {
		return npm.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo)
	}
	// Indirect dependencies are installed as dev and then deleted
	// This effect only the .lock file
	if err := npm.GenericPackageHandler.UpdateImpactedPackage(impactedPackage, fixVersionInfo, "-D"); err != nil {
		return err
	}
	return runPackageMangerCommand(fixVersionInfo.PackageType.GetPackageType(), []string{"uninstall", impactedPackage})
}
