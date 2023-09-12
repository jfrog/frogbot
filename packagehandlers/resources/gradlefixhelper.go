package resources

import (
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"strings"
)

const (
	apostrophes                   = "[\\\"|\\']"
	directMapWithVersionRegexp    = "group:\\s?" + apostrophes + "%s" + apostrophes + ", name:\\s?" + apostrophes + "%s" + apostrophes + ", version:\\s?" + apostrophes + "%s" + apostrophes
	directStringWithVersionRegexp = apostrophes + "%s:%s:%s" + ".*" + apostrophes
)

// TODO case: no version at the end
// TODO case: map with newline in the middle
// TODO case: dynamic version

type VulnRowData struct {
	Content         string
	RowType         string
	FileType        string
	Filepath        string // needed just for some error
	LeftIndentation string //TODO DEL? check if needed to any fixer
}

var RegexpNameToPattern = map[string][]string{
	"directStaticVersion": {directMapWithVersionRegexp, directStringWithVersionRegexp},
}

type VulnerableRowFixer interface {
	GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string
}

// GetFixerByRowType returns suitable fixer object for the row according to the row's type.
// The known types can be found in RegexpNameToPattern map
func GetFixerByRowType(rowData VulnRowData, rowNumberInFile int) (VulnerableRowFixer, error) {
	// TODO put all in ENUM
	switch rowData.RowType {
	case "directStaticVersion":
		return &DirectRowFixer{CommonVulnerableRowFixer{
			rowData:         rowData,
			rowNumberInFile: rowNumberInFile,
		}}, nil
	default:
		return nil, errorutils.CheckErrorf("unknown row type")
	}
}

type CommonVulnerableRowFixer struct {
	rowData         VulnRowData
	rowNumberInFile int // TODO DEL? check if needed
}

func (cvrf *CommonVulnerableRowFixer) GetVulnerableRowFix() string {
	return "common fixer"
}

// DirectRowFixer captures the following types:
// string with version (<configName> 'a:b:c', <configName> "a:b:c") with possibly: additional args after version/single line comment
// map with version (<configName> group: "a", name: "b", version: "c", <configName> group: 'a', name: 'b', version: 'c') with possibly: additional entries after version/single line comment
type DirectRowFixer struct {
	CommonVulnerableRowFixer
}

func (dsrf *DirectRowFixer) GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string {
	fix := strings.Replace(dsrf.rowData.Content, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
	return fix
}
