package resources

import "github.com/jfrog/jfrog-client-go/utils/errorutils"

const (
	directStringWithVersionRegex = "[a-zA-Z]+\\s[\\\"|\\'][a-zA-Z]+:[a-zA-Z]+:[0-9]+\\.[0-9]+\\.?[0-9]*[\\\"|\\']"
)

var RegexpNameToPattern = map[string]string{"directStringWithVersion": directStringWithVersionRegex}

type VulnerableRowFixer interface {
	GetVulnRowFix() string
}

// GetFixerByRowType returns suitable fixer object for the row according to the row's type.
// The known types can be found in RegexpNameToPattern map
func GetFixerByRowType(rowContent string, rowType string, fileType string, filepath string, rowNumberInFile int) (VulnerableRowFixer, error) {
	switch rowType {
	case "directStringWithVersion":
		return &DirectStringRowFixer{CommonVulnerableRowFixer{
			rowContent:      rowContent,
			fileType:        fileType,
			filePath:        filepath,
			rowNumberInFile: rowNumberInFile,
		}}, nil
	default:
		return nil, errorutils.CheckErrorf("unknown row type")
	}
}

type CommonVulnerableRowFixer struct {
	rowContent      string
	fileType        string
	filePath        string //TODO del?
	rowNumberInFile int    // TODO DEL? check if needed
}

func (cvrf *CommonVulnerableRowFixer) GetVulnRowFix() string {
	return "common fixer"
}

type DirectStringRowFixer struct {
	CommonVulnerableRowFixer
}

func (dsrf *DirectStringRowFixer) GetVulnRowFix() string {
	return "direct string fix"
}
