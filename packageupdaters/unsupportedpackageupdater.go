package packageupdaters

import (
	"errors"
	"github.com/jfrog/frogbot/v2/utils"
)

type UnsupportedPackageUpdater struct {
}

func (uph *UnsupportedPackageUpdater) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	return errors.New("frogbot currently does not support opening a pull request that fixes vulnerabilities in " + vulnDetails.Technology.ToFormal())
}
