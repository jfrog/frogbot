package resources

import (
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"strings"
)

const (
	directStringWithVersionRegexp = "[a-zA-Z]+\\s[\\\"|\\'][a-zA-Z-\\.]+:[a-zA-Z-\\.]+:[0-9]+\\.[0-9]+\\.?[0-9]*[:a-zA-Z-\\.0-1]*[\\\"|\\'].*"
	directMapWithVersionRegexp    = "[a-zA-Z]+\\s?group:\\s?[\\\"|\\'].+[\\\"|\\'],\\s?name:\\s?[\\\"|\\'].+[\\\"|\\'],\\s?version:\\s?[\\\"|\\'].+[\\\"|\\'].*"
)

// TODO case: no version at the end
// TODO case: more at the end of the string after the version
// TODO case: map with newline in the middle
// TODO case: wrapped in ()
// TODO case: wrapped in []

type VulnRowData struct {
	Content         string
	RowType         string
	FileType        string
	Filepath        string // TODO DEL? check if needed
	LeftIndentation string //TODO DEL? check if needed to any fixer
}

var RegexpNameToPattern = map[string][]string{
	"directWithVersion": {directStringWithVersionRegexp, directMapWithVersionRegexp},
}

type VulnerableRowFixer interface {
	GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string
}

// GetFixerByRowType returns suitable fixer object for the row according to the row's type.
// The known types can be found in RegexpNameToPattern map
func GetFixerByRowType(rowData VulnRowData, rowNumberInFile int) (VulnerableRowFixer, error) {
	switch rowData.RowType {
	case "directWithVersion":
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
