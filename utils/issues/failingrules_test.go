package issues

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
)

func TestCollectFailingIssuesForPr(t *testing.T) {
	testCases := []struct {
		name           string
		violations     *violationutils.Violations
		expectedIssues []failingIssue
	}{
		{
			name:           "Nil violations",
			violations:     nil,
			expectedIssues: nil,
		},
		{
			name:           "Empty violations",
			violations:     &violationutils.Violations{},
			expectedIssues: nil,
		},
		{
			name: "No fail_pr policies",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "my-watch",
								Policies: []violationutils.Policy{{PolicyName: "pol1", Rule: "rule1", FailBuild: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
			},
			expectedIssues: nil,
		},
		{
			name: "Single SCA violation with fail_pr",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "security-watch",
								Policies: []violationutils.Policy{{PolicyName: "critical-cves", Rule: "block-critical-severity", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "CVE-2026-4800 (lodash@4.17.20)",
					triples:     []ruleTriple{{watch: "security-watch", policy: "critical-cves", rule: "block-critical-severity"}},
				},
			},
		},
		{
			name: "Same CVE+component matched under two watches merges into one issue",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "watch-a",
								Policies: []violationutils.Policy{{PolicyName: "pol-a", Rule: "rule-a", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "watch-b",
								Policies: []violationutils.Policy{{PolicyName: "pol-b", Rule: "rule-b", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "CVE-2026-4800 (lodash@4.17.20)",
					triples: []ruleTriple{
						{watch: "watch-a", policy: "pol-a", rule: "rule-a"},
						{watch: "watch-b", policy: "pol-b", rule: "rule-b"},
					},
				},
			},
		},
		{
			name: "Duplicate watch-policy-rule triple for the same issue is deduplicated",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "watch-a",
								Policies: []violationutils.Policy{{PolicyName: "pol-a", Rule: "rule-a", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "watch-a",
								Policies: []violationutils.Policy{{PolicyName: "pol-a", Rule: "rule-a", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "CVE-2026-4800 (lodash@4.17.20)",
					triples:     []ruleTriple{{watch: "watch-a", policy: "pol-a", rule: "rule-a"}},
				},
			},
		},
		{
			name: "Skip not-applicable CVE when SkipNotApplicable is set",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "watch-skip",
								Policies: []violationutils.Policy{{PolicyName: "pol-skip", Rule: "rule-skip", FailPullRequest: true, SkipNotApplicable: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability:   cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
						ContextualAnalysis: &formats.Applicability{Status: "Not Applicable"},
					},
				},
			},
			expectedIssues: nil,
		},
		{
			name: "Do not skip applicable CVE even when SkipNotApplicable is set",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "watch-applicable",
								Policies: []violationutils.Policy{{PolicyName: "pol-a", Rule: "rule-a", FailPullRequest: true, SkipNotApplicable: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability:   cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
						ContextualAnalysis: &formats.Applicability{Status: "Applicable"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "CVE-2026-4800 (lodash@4.17.20)",
					triples:     []ruleTriple{{watch: "watch-applicable", policy: "pol-a", rule: "rule-a"}},
				},
			},
		},
		{
			name: "Mixed fail_pr and fail_build policies on the same finding - only fail_pr returned",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch: "watch1",
								Policies: []violationutils.Policy{
									{PolicyName: "pol-pr", Rule: "rule-pr", FailPullRequest: true},
									{PolicyName: "pol-build", Rule: "rule-build", FailBuild: true},
								},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "CVE-2026-4800 (lodash@4.17.20)",
					triples:     []ruleTriple{{watch: "watch1", policy: "pol-pr", rule: "rule-pr"}},
				},
			},
		},
		{
			name: "License violation with fail_pr",
			violations: &violationutils.Violations{
				License: []violationutils.LicenseViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "license-watch",
								Policies: []violationutils.Policy{{PolicyName: "banned-licenses", Rule: "block-copyleft", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "requests", Version: "2.25.1"},
						},
						LicenseKey: "GPL-3.0-only",
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "License: GPL-3.0-only (requests@2.25.1)",
					triples:     []ruleTriple{{watch: "license-watch", policy: "banned-licenses", rule: "block-copyleft"}},
				},
			},
		},
		{
			name: "OpRisk violation with fail_pr",
			violations: &violationutils.Violations{
				OpRisk: []violationutils.OperationalRiskViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "oprisk-watch",
								Policies: []violationutils.Policy{{PolicyName: "oprisk-pol", Rule: "oprisk-rule", FailPullRequest: true}},
								Severity: severityutils.High,
							},
							ImpactedComponent: &cyclonedx.Component{Name: "old-lib", Version: "0.1.0"},
						},
						OperationalRiskViolationReadableData: violationutils.OperationalRiskViolationReadableData{RiskReason: "EOL"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "Operational Risk: EOL (old-lib@0.1.0)",
					triples:     []ruleTriple{{watch: "oprisk-watch", policy: "oprisk-pol", rule: "oprisk-rule"}},
				},
			},
		},
		{
			name: "Secrets violation with fail_pr includes location and ruleId in the description",
			violations: &violationutils.Violations{
				Secrets: []violationutils.JasViolation{
					{
						Violation: violationutils.Violation{
							Watch:    "appsec-watch",
							Policies: []violationutils.Policy{{PolicyName: "no-secrets", Rule: "block-any-secret", FailPullRequest: true}},
						},
						Rule: sarif.NewReportingDescriptor().WithID("generic-api-key"),
						Location: sarif.NewLocation().WithPhysicalLocation(
							sarif.NewPhysicalLocation().
								WithArtifactLocation(sarif.NewArtifactLocation().WithURI("secrets/api_secrets/tokens")).
								WithRegion(sarif.NewRegion().WithStartLine(1).WithStartColumn(9)),
						),
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "secrets/api_secrets/tokens:1:9 [rule: generic-api-key]",
					triples:     []ruleTriple{{watch: "appsec-watch", policy: "no-secrets", rule: "block-any-secret"}},
				},
			},
		},
		{
			name: "IaC and SAST violations at different locations produce distinct issues",
			violations: &violationutils.Violations{
				Iac: []violationutils.JasViolation{
					{
						Violation: violationutils.Violation{
							Watch:    "appsec-watch",
							Policies: []violationutils.Policy{{PolicyName: "iac-hardening", Rule: "block-medium-iac", FailPullRequest: true}},
						},
						Rule: sarif.NewReportingDescriptor().WithID("gcp-private-endpoint"),
						Location: sarif.NewLocation().WithPhysicalLocation(
							sarif.NewPhysicalLocation().
								WithArtifactLocation(sarif.NewArtifactLocation().WithURI("iac/gcp/k8s-oss/module.tf")).
								WithRegion(sarif.NewRegion().WithStartLine(19).WithStartColumn(1)),
						),
					},
				},
				Sast: []violationutils.JasViolation{
					{
						Violation: violationutils.Violation{
							Watch:    "appsec-watch",
							Policies: []violationutils.Policy{{PolicyName: "sast-medium", Rule: "block-medium-sast", FailPullRequest: true}},
						},
						Rule: sarif.NewReportingDescriptor().WithID("cleartext-connection"),
						Location: sarif.NewLocation().WithPhysicalLocation(
							sarif.NewPhysicalLocation().
								WithArtifactLocation(sarif.NewArtifactLocation().WithURI("sast/flask_webgoat/__init__.py")).
								WithRegion(sarif.NewRegion().WithStartLine(29).WithStartColumn(12)),
						),
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "iac/gcp/k8s-oss/module.tf:19:1 [rule: gcp-private-endpoint]",
					triples:     []ruleTriple{{watch: "appsec-watch", policy: "iac-hardening", rule: "block-medium-iac"}},
				},
				{
					description: "sast/flask_webgoat/__init__.py:29:12 [rule: cleartext-connection]",
					triples:     []ruleTriple{{watch: "appsec-watch", policy: "sast-medium", rule: "block-medium-sast"}},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := collectFailingIssues(tc.violations, failActionPr)
			assert.Equal(t, tc.expectedIssues, result)
		})
	}
}

func TestCollectFailingIssuesForBuild(t *testing.T) {
	testCases := []struct {
		name           string
		violations     *violationutils.Violations
		expectedIssues []failingIssue
	}{
		{
			name: "No fail_build policies",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "my-watch",
								Policies: []violationutils.Policy{{PolicyName: "pol1", Rule: "rule1", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
			},
			expectedIssues: nil,
		},
		{
			name: "Single SCA violation with fail_build",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "build-watch",
								Policies: []violationutils.Policy{{PolicyName: "build-policy", Rule: "build-rule", FailBuild: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "minimist", Version: "1.2.5"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2021-44906"},
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "CVE-2021-44906 (minimist@1.2.5)",
					triples:     []ruleTriple{{watch: "build-watch", policy: "build-policy", rule: "build-rule"}},
				},
			},
		},
		{
			name: "Mixed fail_pr and fail_build on the same finding - only fail_build returned",
			violations: &violationutils.Violations{
				Secrets: []violationutils.JasViolation{
					{
						Violation: violationutils.Violation{
							Watch: "mixed-watch",
							Policies: []violationutils.Policy{
								{PolicyName: "pol-pr", Rule: "rule-pr", FailPullRequest: true},
								{PolicyName: "pol-build", Rule: "rule-build", FailBuild: true},
							},
						},
						Rule: sarif.NewReportingDescriptor().WithID("generic-secret"),
						Location: sarif.NewLocation().WithPhysicalLocation(
							sarif.NewPhysicalLocation().
								WithArtifactLocation(sarif.NewArtifactLocation().WithURI("secrets/secret_generic/gibberish")).
								WithRegion(sarif.NewRegion().WithStartLine(1).WithStartColumn(1)),
						),
					},
				},
			},
			expectedIssues: []failingIssue{
				{
					description: "secrets/secret_generic/gibberish:1:1 [rule: generic-secret]",
					triples:     []ruleTriple{{watch: "mixed-watch", policy: "pol-build", rule: "rule-build"}},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := collectFailingIssues(tc.violations, failActionBuild)
			assert.Equal(t, tc.expectedIssues, result)
		})
	}
}

func TestLogFailingPolicyRulesForPrDoesNotPanic(t *testing.T) {
	LogFailingPolicyRulesForPr(nil)
	LogFailingPolicyRulesForPr(&violationutils.Violations{})
}

func TestLogFailingPolicyRulesForBuildDoesNotPanic(t *testing.T) {
	LogFailingPolicyRulesForBuild(nil)
	LogFailingPolicyRulesForBuild(&violationutils.Violations{})
}

func TestShouldSkipCvePolicy(t *testing.T) {
	testCases := []struct {
		name     string
		policy   violationutils.Policy
		cve      violationutils.CveViolation
		expected bool
	}{
		{
			name:   "SkipNotApplicable false",
			policy: violationutils.Policy{SkipNotApplicable: false},
			cve:    violationutils.CveViolation{ContextualAnalysis: &formats.Applicability{Status: "Not Applicable"}},
		},
		{
			name:   "SkipNotApplicable true, no contextual analysis",
			policy: violationutils.Policy{SkipNotApplicable: true},
			cve:    violationutils.CveViolation{},
		},
		{
			name:     "SkipNotApplicable true, not applicable",
			policy:   violationutils.Policy{SkipNotApplicable: true},
			cve:      violationutils.CveViolation{ContextualAnalysis: &formats.Applicability{Status: "Not Applicable"}},
			expected: true,
		},
		{
			name:   "SkipNotApplicable true, applicable",
			policy: violationutils.Policy{SkipNotApplicable: true},
			cve:    violationutils.CveViolation{ContextualAnalysis: &formats.Applicability{Status: "Applicable"}},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, shouldSkipCvePolicy(tc.policy, tc.cve))
		})
	}
}

func TestJasIssueIdentity(t *testing.T) {
	v := violationutils.JasViolation{
		Rule: sarif.NewReportingDescriptor().WithID("generic-api-key"),
		Location: sarif.NewLocation().WithPhysicalLocation(
			sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithURI("secrets/api_secrets/tokens")).
				WithRegion(sarif.NewRegion().WithStartLine(1).WithStartColumn(9)),
		),
	}
	_, description := jasIssueIdentity(v)
	assert.Equal(t, "secrets/api_secrets/tokens:1:9 [rule: generic-api-key]", description)
}

func TestRuleTripleString(t *testing.T) {
	assert.Equal(t, "Watch: 'w', Policy: 'p', Rule: 'r'", ruleTriple{watch: "w", policy: "p", rule: "r"}.String())
	// Xray does not provide a rule name for JAS (Secrets/IaC/SAST) violations - it must be omitted, not printed empty.
	assert.Equal(t, "Watch: 'w', Policy: 'p'", ruleTriple{watch: "w", policy: "p"}.String())
}

func TestResolveViolations_NilScanResults(t *testing.T) {
	assert.Nil(t, ResolveViolations(nil))
}

// jfrog-cli-security can leave scanResults.Violations as a non-nil pointer to an EMPTY
// violationutils.Violations{} even when real violations exist in the legacy per-target results
// (its EnrichWithGeneratedViolations calls SetViolations unconditionally, including when its
// generator no-ops). ResolveViolations must ignore that misleading top-level field entirely and
// always derive from Targets, so a "populated but empty" top-level value must not suppress the
// real violation found in DeprecatedXrayResults.
func TestResolveViolations_IgnoresMisleadingEmptyTopLevelViolations(t *testing.T) {
	scanResults := &results.SecurityCommandResults{
		Violations: &violationutils.Violations{}, // non-nil, but empty - exactly what jfrog-cli-security leaves behind when its own violation-fetch step no-ops
		Targets: []*results.TargetResults{
			{
				ScanTarget: results.ScanTarget{Target: "."},
				ScaResults: &results.ScaScanResults{
					DeprecatedXrayResults: []services.ScanResponse{
						{
							Violations: []services.Violation{
								{
									WatchName:     "security-watch",
									ViolationType: violationutils.ScaViolationTypeSecurity.String(),
									Severity:      "High",
									IssueId:       "XRAY-140308", // Xray's internal issue ID - must NOT end up in the log description
									Cves:          []services.Cve{{Id: "CVE-2026-4800"}},
									Components:    map[string]services.Component{"npm://lodash:4.17.20": {}},
									FailBuild:     true,
									Policies:      []services.Policy{{Policy: "critical-cves", Rule: "block-critical-severity"}},
								},
							},
						},
					},
				},
			},
		},
	}

	resolved := ResolveViolations(scanResults)
	assert.NotNil(t, resolved)

	issuesFound := collectFailingIssues(resolved, failActionBuild)
	assert.Equal(t, []failingIssue{
		{
			description: "CVE-2026-4800 (lodash@4.17.20)",
			triples:     []ruleTriple{{watch: "security-watch", policy: "critical-cves", rule: "block-critical-severity"}},
		},
	}, issuesFound)
}

func TestResolveViolations_EmptyTargets_ReturnsEmptyNonNilViolations(t *testing.T) {
	scanResults := &results.SecurityCommandResults{}
	resolved := ResolveViolations(scanResults)
	assert.NotNil(t, resolved)
	assert.Empty(t, resolved.Sca)
	assert.Empty(t, resolved.Secrets)
}

func TestResolveViolations_DerivesFromLegacySCAViolation(t *testing.T) {
	scanResults := &results.SecurityCommandResults{
		Targets: []*results.TargetResults{
			{
				ScanTarget: results.ScanTarget{Target: "."},
				ScaResults: &results.ScaScanResults{
					DeprecatedXrayResults: []services.ScanResponse{
						{
							Violations: []services.Violation{
								{
									WatchName:     "security-watch",
									ViolationType: violationutils.ScaViolationTypeSecurity.String(),
									Severity:      "High",
									IssueId:       "XRAY-140308", // Xray's internal issue ID - must NOT end up in the log description
									Cves:          []services.Cve{{Id: "CVE-2026-4800"}},
									Components:    map[string]services.Component{"npm://lodash:4.17.20": {}},
									FailBuild:     true,
									Policies:      []services.Policy{{Policy: "critical-cves", Rule: "block-critical-severity"}},
								},
							},
						},
					},
				},
			},
		},
	}

	resolved := ResolveViolations(scanResults)
	assert.NotNil(t, resolved)

	issuesFound := collectFailingIssues(resolved, failActionBuild)
	assert.Equal(t, []failingIssue{
		{
			description: "CVE-2026-4800 (lodash@4.17.20)",
			triples:     []ruleTriple{{watch: "security-watch", policy: "critical-cves", rule: "block-critical-severity"}},
		},
	}, issuesFound)
}
