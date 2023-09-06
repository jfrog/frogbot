package packagehandlers

import "github.com/jfrog/frogbot/utils"

type GradlePackageHandler struct {
	CommonPackageHandler
}

func (gph *GradlePackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	// TODO check which kind of dependencies are being supported here in gradle (direct, with/without var, scripts?, plugins?, projects?)
	if vulnDetails.IsDirectDependency {
		return gph.updateDirectDependency(vulnDetails)
	}

	return &utils.ErrUnsupportedFix{
		PackageName:  vulnDetails.ImpactedDependencyName,
		FixedVersion: vulnDetails.SuggestedFixedVersion,
		ErrorType:    utils.IndirectDependencyFixNotSupported,
	}
}

func (gph *GradlePackageHandler) updateDirectDependency(vulnDetails *utils.VulnerabilityDetails) (err error) {
	// TODO implement main logic here
	return nil
}
