package resources

type vulnerableRowFixer interface {
	fixVulnerableRow(vulnRow string) string
}

type CommonVulnerableRow struct{}

func (cvr *CommonVulnerableRow) fixVulnerableRow(vulnRow string) string {
	return "" //TODO is this the correct way to do that?
}

type DirectStringRow struct {
	CommonVulnerableRow
}
