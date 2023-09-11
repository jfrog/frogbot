package resources

import (
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"strings"
)

const (
	directStringWithVersionRegex = "[a-zA-Z]+\\s[\\\"|\\'][a-zA-Z]+:[a-zA-Z]+:[0-9]+\\.[0-9]+\\.?[0-9]*[\\\"|\\']"
)

// TODO case: no version at the end
// TODO case: more at the end of the string after the version
// TODO case: map with newline in the middle

type VulnRowData struct {
	Content         string
	RowType         string
	FileType        string
	Filepath        string // TODO DEL? check if needed
	LeftIndentation string //TODO DEL? check if needed to any fixer
}

var RegexpNameToPattern = map[string]string{"directStringWithVersion": directStringWithVersionRegex}

type VulnerableRowFixer interface {
	GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string
}

// GetFixerByRowType returns suitable fixer object for the row according to the row's type.
// The known types can be found in RegexpNameToPattern map
func GetFixerByRowType(rowData VulnRowData, rowNumberInFile int) (VulnerableRowFixer, error) {
	switch rowData.RowType {
	case "directStringWithVersion":
		return &DirectStringRowFixer{CommonVulnerableRowFixer{
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

type DirectStringRowFixer struct {
	CommonVulnerableRowFixer
}

func (dsrf *DirectStringRowFixer) GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string {
	fix := strings.Replace(dsrf.rowData.Content, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
	return fix
}
