package resources

import (
	"github.com/jfrog/frogbot/utils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"strings"
)

type RowType string

const (
	apostrophes                           = "[\\\"|\\']"
	directMapWithVersionRegexp            = "group\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", name\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes + ", version\\s?[:|=]\\s?" + apostrophes + "%s" + apostrophes
	directStringWithVersionRegexp         = apostrophes + "%s:%s:%s" + ".*" + apostrophes
	DirectStaticVersion           RowType = "directStaticVersion"
	UnsupportedLineFormat         RowType = "vulnerable package detected with unsupported pattern in line"
	UnknownRowType                RowType = "unknown"
)

type VulnRowData struct {
	Content  string
	RowType  RowType // DELETE IF NOT SEPARATING BY ROW TYPE
	FileType string  // Needed???
	Filepath string
}

var RegexpNameToPattern = map[RowType][]string{
	DirectStaticVersion: {directMapWithVersionRegexp, directStringWithVersionRegexp},
}

type VulnerableRowFixer interface {
	GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string
}

// GetFixerByRowType returns suitable fixer object for the row according to the row's type.
// The known types can be found in RegexpNameToPattern map
func GetFixerByRowType(rowData VulnRowData, rowNumberInFile int) (VulnerableRowFixer, error) {
	switch rowData.RowType {
	case DirectStaticVersion:
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

// DirectRowFixer captures the following types: todo complete
// string with version (<configName> 'a:b:c', <configName> "a:b:c") with possibly: additional args after version/single line comment
// map with version (<configName> group: "a", name: "b", version: "c", <configName> group: 'a', name: 'b', version: 'c') with possibly: additional entries after version/single line comment
type DirectRowFixer struct {
	CommonVulnerableRowFixer
}

func (dsrf *DirectRowFixer) GetVulnerableRowFix(vulnDetails *utils.VulnerabilityDetails) string {
	fix := strings.Replace(dsrf.rowData.Content, vulnDetails.ImpactedDependencyVersion, vulnDetails.SuggestedFixedVersion, 1)
	return fix
}
