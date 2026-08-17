package issues

import (
	"fmt"
	"sort"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const violationUiLinkMinXrayVersion = "3.150.4"

type failAction int

const (
	failActionPr failAction = iota
	failActionBuild
)

type violationTrigger struct {
	watch  string
	policy string
	rule   string
}

func (t violationTrigger) String() string {
	return fmt.Sprintf("Watch: '%s', Policy: '%s', Rule: '%s'", t.watch, t.policy, t.rule)
}

type failingIssue struct {
	description string
	violationId string
	triggers    []violationTrigger
}

func LogFailingPolicyRulesForPr(violations *violationutils.Violations, server *config.ServerDetails, xrayVersion string) {
	logFailingPolicyRules(violations, failActionPr, violationUiBaseUrl(server, xrayVersion))
}

func LogFailingPolicyRulesForBuild(violations *violationutils.Violations, server *config.ServerDetails, xrayVersion string) {
	logFailingPolicyRules(violations, failActionBuild, violationUiBaseUrl(server, xrayVersion))
}

func logFailingPolicyRules(violations *violationutils.Violations, action failAction, baseUrl string) {
	if violations == nil {
		return
	}
	issuesFound := collectFailingIssues(violations, action)
	if len(issuesFound) == 0 {
		return
	}
	logFailingIssues(issuesFound, action, baseUrl)
}

func collectFailingIssues(violations *violationutils.Violations, action failAction) []failingIssue {
	if violations == nil {
		return nil
	}
	byKey := map[string]*failingIssue{}
	seenTriggers := map[string]map[string]bool{}

	addTrigger := func(issueKey, description, violationId, watch string, p violationutils.Policy) {
		issue, exists := byKey[issueKey]
		if !exists {
			issue = &failingIssue{description: description, violationId: violationId}
			byKey[issueKey] = issue
			seenTriggers[issueKey] = map[string]bool{}
		}
		triggerKey := fmt.Sprintf("%s|%s|%s", watch, p.PolicyName, p.Rule)
		if seenTriggers[issueKey][triggerKey] {
			return
		}
		seenTriggers[issueKey][triggerKey] = true
		issue.triggers = append(issue.triggers, violationTrigger{watch: watch, policy: p.PolicyName, rule: p.Rule})
	}

	for _, v := range violations.Sca {
		key, description := scaIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) || shouldSkipCvePolicy(p, v) {
				continue
			}
			addTrigger(key, description, v.ViolationId, v.Watch, p)
		}
	}
	for _, v := range violations.License {
		key, description := licenseIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) {
				continue
			}
			addTrigger(key, description, v.ViolationId, v.Watch, p)
		}
	}
	for _, v := range violations.OpRisk {
		key, description := opRiskIssueIdentity(v)
		for _, p := range v.Policies {
			if !isFailActionMatched(p, action) {
				continue
			}
			addTrigger(key, description, v.ViolationId, v.Watch, p)
		}
	}

	// TODO Iac is always empty here until jfrog-cli-security's PolicyEnforcerViolationGenerator adds IaC support (remove this when solved in jfrog-cli-security)
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
			addTrigger(key, description, v.ViolationId, v.Watch, p)
		}
	}

	var issuesFound []failingIssue
	for _, issue := range byKey {
		sort.Slice(issue.triggers, func(i, j int) bool {
			if issue.triggers[i].watch != issue.triggers[j].watch {
				return issue.triggers[i].watch < issue.triggers[j].watch
			}
			if issue.triggers[i].policy != issue.triggers[j].policy {
				return issue.triggers[i].policy < issue.triggers[j].policy
			}
			return issue.triggers[i].rule < issue.triggers[j].rule
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

func logFailingIssues(issuesFound []failingIssue, action failAction, baseUrl string) {
	log.Info(renderFailingIssues(issuesFound, action, baseUrl))
}

func renderFailingIssues(issuesFound []failingIssue, action failAction, baseUrl string) string {
	var lines []string
	for _, issue := range issuesFound {
		lines = append(lines, "  - "+issue.description)
		if link := violationUiLink(baseUrl, issue.violationId); link != "" {
			lines = append(lines, "      Violation: "+link)
		}
		lines = append(lines, "      Triggered:")
		for _, t := range issue.triggers {
			lines = append(lines, "        - "+t.String())
		}
	}
	actionDesc := "the pull request"
	if action == failActionBuild {
		actionDesc = "the build"
	}
	return fmt.Sprintf(
		"The following findings triggered a policy rule configured to fail %s:\n%s",
		actionDesc,
		strings.Join(lines, "\n"),
	)
}

func violationUiBaseUrl(server *config.ServerDetails, xrayVersion string) string {
	if err := clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, violationUiLinkMinXrayVersion); err != nil {
		return ""
	}
	if server.Url != "" {
		return strings.TrimSuffix(server.Url, "/")
	}
	return strings.TrimSuffix(strings.TrimSuffix(server.XrayUrl, "/"), "/xray")
}

func violationUiLink(baseUrl, violationId string) string {
	if baseUrl == "" || violationId == "" {
		return ""
	}
	return baseUrl + "/ui/violations/" + violationId
}
