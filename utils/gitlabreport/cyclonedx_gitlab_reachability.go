package gitlabreport

import (
	"fmt"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// GitLab documents native "Reachable" (Yes / Not Found / Not Available) from CycloneDX
// component properties, not from gl-dependency-scanning-report.json details.
// See: https://docs.gitlab.com/development/sec/cyclonedx_property_taxonomy/
const (
	gitlabMetaSchemaVersionProp           = "gitlab:meta:schema_version"
	gitlabDependencyScanningInputFilePath = "gitlab:dependency_scanning:input_file:path"
	gitlabDependencyScanningReachability  = "gitlab:dependency_scanning_component:reachability"
	gitlabReachabilityInUse               = "in_use"
	gitlabReachabilityNotFound            = "not_found"
)

// reachRank orders contextual-analysis outcomes for merging multiple findings on one dependency.
type reachRank int

const (
	reachNone reachRank = iota
	reachNotFound
	reachInUse
)

// EnrichCycloneDXBOMForGitLabReachability adds GitLab CycloneDX properties so the Security UI
// "Reachable" field reflects JFrog contextual analysis (applicability): Applicable → in_use (Yes),
// other assessed outcomes → not_found (Not Found), no applicability data → omit (Not Available).
//
// GitLab only merges SBOM reachability into findings when the BOM is uploaded as a CycloneDX
// report (artifacts:reports:cyclonedx), not as a generic artifact path alone.
func EnrichCycloneDXBOMForGitLabReachability(bom *cyclonedx.BOM, scanResults *results.SecurityCommandResults) {
	if bom == nil || scanResults == nil {
		return
	}
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}
	bom.Metadata.Properties = cdxutils.AppendProperties(bom.Metadata.Properties, cyclonedx.Property{
		Name:  gitlabMetaSchemaVersionProp,
		Value: "1",
	})

	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: true,
		HasViolationContext:    scanResults.HasViolationContext(),
	})
	simpleJSON, err := convertor.ConvertToSimpleJson(scanResults)
	if err != nil {
		log.Warn(fmt.Sprintf("GitLab reachability: skipping CycloneDX enrichment, simple JSON conversion failed: %v", err))
		return
	}

	depInfo := make(map[string]*depReachInfo)
	for i := range simpleJSON.Vulnerabilities {
		mergeRowReachability(depInfo, &simpleJSON.Vulnerabilities[i])
	}
	for i := range simpleJSON.SecurityViolations {
		mergeRowReachability(depInfo, &simpleJSON.SecurityViolations[i])
	}

	if bom.Metadata.Component != nil {
		walkComponentTree(bom.Metadata.Component, depInfo)
	}
	walkComponentSlice(bom.Components, depInfo)
}

// depReachInfo holds merged reachability and a manifest path for GitLab SBOM correlation.
type depReachInfo struct {
	rank      reachRank
	inputFile string
}

func mergeRowReachability(depInfo map[string]*depReachInfo, v *formats.VulnerabilityOrViolationRow) {
	r, ok := gitlabReachabilityRankForRow(v)
	if !ok {
		return
	}
	inFile := rowPreferredInputFile(v)
	for _, key := range rowDependencyKeys(v) {
		if key == "" {
			continue
		}
		cur := depInfo[key]
		if cur == nil {
			cur = &depReachInfo{}
			depInfo[key] = cur
		}
		if r > cur.rank {
			cur.rank = r
			if inFile != "" {
				cur.inputFile = inFile
			}
		} else if r == cur.rank && cur.inputFile == "" && inFile != "" {
			cur.inputFile = inFile
		}
	}
}

// rowPreferredInputFile picks a repo-relative lock/manifest path for gitlab:dependency_scanning:input_file:path.
func rowPreferredInputFile(v *formats.VulnerabilityOrViolationRow) string {
	for _, comp := range v.Components {
		if comp.PreferredLocation != nil {
			if f := strings.TrimSpace(comp.PreferredLocation.File); f != "" {
				return f
			}
		}
		for _, ev := range comp.Evidences {
			if f := strings.TrimSpace(ev.File); f != "" {
				return f
			}
		}
	}
	return strings.TrimSpace(manifestFileForTechnology(v.Technology))
}

func rowDependencyKeys(v *formats.VulnerabilityOrViolationRow) []string {
	name := strings.TrimSpace(v.ImpactedDependencyName)
	ver := strings.TrimSpace(v.ImpactedDependencyVersion)
	if name == "" {
		return nil
	}
	return []string{dependencyReachabilityKey(name, ver)}
}

func dependencyReachabilityKey(name, version string) string {
	return name + "\x00" + version
}

// gitlabReachabilityRankForRow maps aggregated contextual analysis to GitLab reachability ranks.
func gitlabReachabilityRankForRow(v *formats.VulnerabilityOrViolationRow) (reachRank, bool) {
	switch rowFinalApplicabilityStatus(v) {
	case jasutils.NotScanned:
		return reachNone, false
	case jasutils.Applicable:
		return reachInUse, true
	default:
		return reachNotFound, true
	}
}

func walkComponentSlice(list *[]cyclonedx.Component, depInfo map[string]*depReachInfo) {
	if list == nil {
		return
	}
	for i := range *list {
		walkComponentTree(&(*list)[i], depInfo)
	}
}

func walkComponentTree(c *cyclonedx.Component, depInfo map[string]*depReachInfo) {
	if c == nil {
		return
	}
	if info := bestReachInfoForComponent(c, depInfo); info != nil && info.rank > reachNone {
		if info.inputFile != "" {
			c.Properties = cdxutils.AppendProperties(c.Properties, cyclonedx.Property{
				Name:  gitlabDependencyScanningInputFilePath,
				Value: info.inputFile,
			})
		}
		val := gitlabReachabilityNotFound
		if info.rank == reachInUse {
			val = gitlabReachabilityInUse
		}
		c.Properties = cdxutils.AppendProperties(c.Properties, cyclonedx.Property{
			Name:  gitlabDependencyScanningReachability,
			Value: val,
		})
	}
	walkComponentSlice(c.Components, depInfo)
}

func bestReachInfoForComponent(c *cyclonedx.Component, depInfo map[string]*depReachInfo) *depReachInfo {
	var best *depReachInfo
	for _, key := range componentDependencyMatchKeys(c) {
		if cur := depInfo[key]; cur != nil && (best == nil || cur.rank > best.rank) {
			best = cur
		}
	}
	return best
}

func componentDependencyMatchKeys(c *cyclonedx.Component) []string {
	name := strings.TrimSpace(c.Name)
	ver := strings.TrimSpace(c.Version)
	if name == "" {
		return nil
	}
	var keys []string
	if g := strings.TrimSpace(c.Group); g != "" {
		keys = append(keys, dependencyReachabilityKey(g+":"+name, ver))
	}
	keys = append(keys, dependencyReachabilityKey(name, ver))
	return keys
}
