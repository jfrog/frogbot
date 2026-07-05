package issues

import (
	"fmt"
	"sort"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/policy/local"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type failAction int

const (
	failActionPr failAction = iota
	failActionBuild
)

type ruleTriple struct {
	watch  string
	policy string
	rule   string
}

func (t ruleTriple) String() string {
	// Rule name is not available for JAS (Secrets/IaC/SAST) violations - Xray does not provide it.
	if t.rule == "" {
		return fmt.Sprintf("Watch: '%s', Policy: '%s'", t.watch, t.policy)
	}
	return fmt.Sprintf("Watch: '%s', Policy: '%s', Rule: '%s'", t.watch, t.policy, t.rule)
}

// failingIssue groups every watch/policy/rule triple that a single finding triggered.
// description uses the same identifying values shown in the findings table (CVE+component,
// license+component, risk reason+component, or file:line:column+ruleId), so the log can be
// cross-referenced against the corresponding table row.
type failingIssue struct {
	description string
	triples     []ruleTriple
}

func LogFailingPolicyRulesForPr(violations *violationutils.Violations) {
	logFailingPolicyRules(violations, failActionPr)
}

func LogFailingPolicyRulesForBuild(violations *violationutils.Violations) {
	logFailingPolicyRules(violations, failActionBuild)
}

func ResolveViolations(scanResults *results.SecurityCommandResults) *violationutils.Violations {
	if scanResults == nil {
		return nil
	}
	generated, err := local.NewDeprecatedViolationGenerator().GenerateViolations(scanResults)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to generate violations from scan results for policy rule logging: %s", err.Error()))
		return nil
	}
	return &generated
}

func logFailingPolicyRules(violations *violationutils.Violations, action failAction) {
	if violations == nil {
		return
	}
	issuesFound := collectFailingIssues(violations, action)
	if len(issuesFound) == 0 {
		return
	}
	logFailingIssues(issuesFound, action)
}

func collectFailingIssues(violations *violationutils.Violations, action failAction) []failingIssue {
	if violations == nil {
		return nil
	}
	byKey := map[string]*failingIssue{}
	seenTriples := map[string]map[string]bool{}

	addTriple := func(issueKey, description, watch string, p violationutils.Policy) {
		issue, exists := byKey[issueKey]
		if !exists {
			issue = &failingIssue{description: description}
			byKey[issueKey] = issue
			seenTriples[issueKey] = map[string]bool{}
		}
		tripleKey := fmt.Sprintf("%s|%s|%s", watch, p.PolicyName, p.Rule)
		if seenTriples[issueKey][tripleKey] {
			return
		}
		seenTriples[issueKey][tripleKey] = true
		issue.triples = append(issue.triples, ruleTriple{watch: watch, policy: p.PolicyName, rule: p.Rule})
	}

	// Sca, License, and Operational Risk violations
	// Skipping not-applicable violations
	for _, v := range violations.Sca {
		key, description := scaIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) || shouldSkipCvePolicy(p, v) {
				continue
			}
			addTriple(key, description, v.Watch, p)
		}
	}
	for _, v := range violations.License {
		key, description := licenseIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) {
				continue
			}
			addTriple(key, description, v.Watch, p)
		}
	}
	for _, v := range violations.OpRisk {
		key, description := opRiskIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) {
				continue
			}
			addTriple(key, description, v.Watch, p)
		}
	}

	// JAS violations
	allJas := make([]violationutils.JasViolation, 0, len(violations.Secrets)+len(violations.Iac)+len(violations.Sast))
	allJas = append(allJas, violations.Secrets...)
	allJas = append(allJas, violations.Iac...)
	allJas = append(allJas, violations.Sast...)

	for _, v := range allJas {
		key, description := jasIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) {
				continue
			}
			addTriple(key, description, v.Watch, p)
		}
	}

	var issuesFound []failingIssue
	for _, issue := range byKey {
		sort.Slice(issue.triples, func(i, j int) bool {
			if issue.triples[i].watch != issue.triples[j].watch {
				return issue.triples[i].watch < issue.triples[j].watch
			}
			if issue.triples[i].policy != issue.triples[j].policy {
				return issue.triples[i].policy < issue.triples[j].policy
			}
			return issue.triples[i].rule < issue.triples[j].rule
		})
		issuesFound = append(issuesFound, *issue)
	}
	sort.Slice(issuesFound, func(i, j int) bool {
		return issuesFound[i].description < issuesFound[j].description
	})
	return issuesFound
}

func scaIssueIdentity(v violationutils.CveViolation) (key, description string) {
	cveId := v.CveVulnerability.BOMRef
	name, version := impactedComponentNameVersion(v.ImpactedComponent)
	key = fmt.Sprintf("sca|%s|%s|%s", cveId, name, version)
	description = fmt.Sprintf("%s (%s@%s)", cveId, name, version)
	return
}

func licenseIssueIdentity(v violationutils.LicenseViolation) (key, description string) {
	name, version := impactedComponentNameVersion(v.ImpactedComponent)
	key = fmt.Sprintf("license|%s|%s|%s", v.LicenseKey, name, version)
	description = fmt.Sprintf("License: %s (%s@%s)", v.LicenseKey, name, version)
	return
}

func opRiskIssueIdentity(v violationutils.OperationalRiskViolation) (key, description string) {
	name, version := impactedComponentNameVersion(v.ImpactedComponent)
	key = fmt.Sprintf("oprisk|%s|%s|%s", v.RiskReason, name, version)
	description = fmt.Sprintf("Operational Risk: %s (%s@%s)", v.RiskReason, name, version)
	return
}

func impactedComponentNameVersion(component *cyclonedx.Component) (name, version string) {
	if component == nil {
		return "", ""
	}
	return component.Name, component.Version
}

func jasIssueIdentity(v violationutils.JasViolation) (key, description string) {
	locationId := sarifutils.GetLocationId(v.Location)
	ruleId := sarifutils.GetRuleId(v.Rule)
	file := sarifutils.GetLocationFileName(v.Location)
	line := sarifutils.GetLocationStartLine(v.Location)
	column := sarifutils.GetLocationStartColumn(v.Location)
	key = fmt.Sprintf("jas|%s|%s", locationId, ruleId)
	description = fmt.Sprintf("%s:%d:%d [rule: %s]", file, line, column, ruleId)
	return
}

func shouldSkipCvePolicy(p violationutils.Policy, v violationutils.CveViolation) bool {
	if !p.SkipNotApplicable {
		return false
	}
	if v.ContextualAnalysis == nil {
		return false
	}
	return jasutils.ConvertToApplicabilityStatus(v.ContextualAnalysis.Status) == jasutils.NotApplicable
}

func isFailActionMatched(p violationutils.Policy, action failAction) bool {
	switch action {
	case failActionPr:
		return p.FailPullRequest
	case failActionBuild:
		return p.FailBuild
	}
	return false
}

func logFailingIssues(issuesFound []failingIssue, action failAction) {
	var lines []string
	for _, issue := range issuesFound {
		lines = append(lines, "  - "+issue.description)
		lines = append(lines, "      Triggered:")
		for _, t := range issue.triples {
			lines = append(lines, "        - "+t.String())
		}
	}
	actionDesc := "the pull request"
	if action == failActionBuild {
		actionDesc = "the build"
	}
	log.Info(fmt.Sprintf(
		"The following findings triggered a policy rule configured to fail %s:\n%s",
		actionDesc,
		strings.Join(lines, "\n"),
	))
}
