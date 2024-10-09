package packagehandlers

import (
	"errors"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
)

type UnsupportedPackageHandler struct {
}

func (uph *UnsupportedPackageHandler) UpdateDependency(vulnDetails *utils.VulnerabilityDetails) error {
	return errors.New("frogbot currently does not support scanning vulnerabilities in " + vulnDetails.Technology.ToFormal())
}

func (uph *UnsupportedPackageHandler) SetCommonParams(serverDetails *config.ServerDetails, depsRepo string) {
}
