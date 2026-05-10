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
// "Reachable" field reflects JFrog contextual analysis: Applicable → in_use, other assessed → not_found,
// no applicability data → omitted (shows as "Not Available").
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

	// When the whole scan uses one lockfile (typical), set it on metadata too so GitLab can
	// correlate SBOM reachability with dependency-scanning findings (per taxonomy).
	if f := uniqueInputFileFromDepInfo(depInfo); f != "" {
		bom.Metadata.Properties = cdxutils.AppendProperties(bom.Metadata.Properties, cyclonedx.Property{
			Name:  gitlabDependencyScanningInputFilePath,
			Value: f,
		})
	}

	if bom.Metadata.Component != nil {
		walkComponentTree(bom.Metadata.Component, depInfo)
	}
	walkComponentSlice(bom.Components, depInfo)
}

type depReachInfo struct {
	rank      reachRank
	inputFile string
}

// uniqueInputFileFromDepInfo returns the single lock/manifest file shared by all assessed dependencies,
// or empty if there are zero or more than one (multiple lockfiles: do not guess metadata-level path).
func uniqueInputFileFromDepInfo(depInfo map[string]*depReachInfo) string {
	seen := make(map[string]struct{})
	for _, info := range depInfo {
		if info == nil || info.rank <= reachNone {
			continue
		}
		if f := strings.TrimSpace(info.inputFile); f != "" {
			seen[f] = struct{}{}
		}
	}
	if len(seen) == 1 {
		for f := range seen {
			return f
		}
	}
	return ""
}

func mergeRowReachability(depInfo map[string]*depReachInfo, v *formats.VulnerabilityOrViolationRow) {
	r, ok := gitlabReachabilityRankForRow(v)
	if !ok {
		return
	}
	name := strings.TrimSpace(v.ImpactedDependencyName)
	if name == "" {
		return
	}
	key := dependencyReachabilityKey(name, strings.TrimSpace(v.ImpactedDependencyVersion))
	inFile := rowPreferredInputFile(v)
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

func dependencyReachabilityKey(name, version string) string {
	return name + "\x00" + version
}

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
	if idx := strings.Index(c.PackageURL, "?"); idx != -1 {
		c.PackageURL = c.PackageURL[:idx]
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
