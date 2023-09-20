package packagehandlers

import (
	"github.com/jfrog/frogbot/utils"
)

const dotnetPackageUpgradeExtraArg = "package"

type NugetPackageHandler struct {
	CommonPackageHandler
}

func (nph *NugetPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	if vulnDetails.IsDirectDependency {
		return nph.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (nph *NugetPackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	//wd, err := os.Getwd()
	//if err != nil {
	//	return
	//}
	//buildFilesDirPath := filepath.Join(wd, "obj")
	//exists, err := fileutils.IsDirExists(buildFilesDirPath, false)
	err = nph.CommonPackageHandler.UpdateDependency(vulnDetails, vulnDetails.Technology.GetPackageInstallationCommand(), dotnetPackageUpgradeExtraArg)
	if err != nil {
		return
	}

	//if !exists {
	//	err = fileutils.RemoveTempDir(buildFilesDirPath)
	//}
	return
}
