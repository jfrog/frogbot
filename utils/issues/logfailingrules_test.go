package issues

import (
	"os"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
					triggers:    []violationTrigger{{watch: "security-watch", policy: "critical-cves", rule: "block-critical-severity"}},
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
					triggers: []violationTrigger{
						{watch: "watch-a", policy: "pol-a", rule: "rule-a"},
						{watch: "watch-b", policy: "pol-b", rule: "rule-b"},
					},
				},
			},
		},
		{
			name: "Duplicate watch-policy-rule trigger for the same issue is deduplicated",
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
					triggers:    []violationTrigger{{watch: "watch-a", policy: "pol-a", rule: "rule-a"}},
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
					triggers:    []violationTrigger{{watch: "watch-applicable", policy: "pol-a", rule: "rule-a"}},
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
					triggers:    []violationTrigger{{watch: "watch1", policy: "pol-pr", rule: "rule-pr"}},
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
					triggers:    []violationTrigger{{watch: "license-watch", policy: "banned-licenses", rule: "block-copyleft"}},
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
					triggers:    []violationTrigger{{watch: "oprisk-watch", policy: "oprisk-pol", rule: "oprisk-rule"}},
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
					triggers:    []violationTrigger{{watch: "appsec-watch", policy: "no-secrets", rule: "block-any-secret"}},
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
					triggers:    []violationTrigger{{watch: "appsec-watch", policy: "iac-hardening", rule: "block-medium-iac"}},
				},
				{
					description: "sast/flask_webgoat/__init__.py:29:12 [rule: cleartext-connection]",
					triggers:    []violationTrigger{{watch: "appsec-watch", policy: "sast-medium", rule: "block-medium-sast"}},
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
					triggers:    []violationTrigger{{watch: "build-watch", policy: "build-policy", rule: "build-rule"}},
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
					triggers:    []violationTrigger{{watch: "mixed-watch", policy: "pol-build", rule: "rule-build"}},
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

func TestViolationTriggerString(t *testing.T) {
	assert.Equal(t, "Watch: 'w', Policy: 'p', Rule: 'r'", violationTrigger{watch: "w", policy: "p", rule: "r"}.String())
}

func TestRenderedFailingIssues(t *testing.T) {
	testCases := []struct {
		name         string
		violations   *violationutils.Violations
		action       failAction
		expectedFile string
	}{
		{
			name: "Scan Repository (fail_build)",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "security-watch",
								Policies: []violationutils.Policy{{PolicyName: "critical-cves", Rule: "block-critical-severity", FailBuild: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "lodash", Version: "4.17.20"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2026-4800"},
					},
				},
				License: []violationutils.LicenseViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "license-watch",
								Policies: []violationutils.Policy{{PolicyName: "banned-licenses", Rule: "block-copyleft", FailBuild: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "requests", Version: "2.25.1"},
						},
						LicenseKey: "GPL-3.0-only",
					},
				},
				OpRisk: []violationutils.OperationalRiskViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "oprisk-watch",
								Policies: []violationutils.Policy{{PolicyName: "eol-policy", Rule: "block-eol", FailBuild: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "old-lib", Version: "0.1.0"},
						},
						OperationalRiskViolationReadableData: violationutils.OperationalRiskViolationReadableData{RiskReason: "EOL"},
					},
				},
				Secrets: []violationutils.JasViolation{
					jasFindingFixture("appsec-watch", "no-secrets", "block-any-secret", "generic-api-key", "secrets/api_secrets/tokens", 1, 9),
				},
				Iac: []violationutils.JasViolation{
					jasFindingFixture("appsec-watch", "iac-hardening", "block-medium-iac", "gcp-private-endpoint", "iac/gcp/k8s-oss/module.tf", 19, 1),
				},
				Sast: []violationutils.JasViolation{
					jasFindingFixture("appsec-watch", "sast-medium", "block-medium-sast", "cleartext-connection", "sast/flask_webgoat/__init__.py", 29, 12),
				},
			},
			action:       failActionBuild,
			expectedFile: "../../testdata/logfailingrules/fail_build_results.txt",
		},
		{
			name: "Scan Pull Request (fail_pull_request)",
			violations: &violationutils.Violations{
				Sca: []violationutils.CveViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "pr-security-watch",
								Policies: []violationutils.Policy{{PolicyName: "high-cves", Rule: "block-high-severity", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "snyk", Version: "1.995.0"},
						},
						CveVulnerability: cyclonedx.Vulnerability{BOMRef: "CVE-2025-6624"},
					},
				},
				License: []violationutils.LicenseViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "pr-license-watch",
								Policies: []violationutils.Policy{{PolicyName: "strict-oss-policy", Rule: "block-non-permissive", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "some-lib", Version: "1.0.0"},
						},
						LicenseKey: "AGPL-3.0",
					},
				},
				OpRisk: []violationutils.OperationalRiskViolation{
					{
						ScaViolation: violationutils.ScaViolation{
							Violation: violationutils.Violation{
								Watch:    "pr-oprisk-watch",
								Policies: []violationutils.Policy{{PolicyName: "deprecated-policy", Rule: "block-deprecated", FailPullRequest: true}},
							},
							ImpactedComponent: &cyclonedx.Component{Name: "old-pkg", Version: "0.9.0"},
						},
						OperationalRiskViolationReadableData: violationutils.OperationalRiskViolationReadableData{RiskReason: "Deprecated"},
					},
				},
				Secrets: []violationutils.JasViolation{
					jasFindingFixture("pr-appsec-watch", "no-secrets-pr", "block-any-secret-pr", "generic-secret", "secrets/secret_generic/gibberish", 1, 1),
				},
				Iac: []violationutils.JasViolation{
					jasFindingFixture("pr-appsec-watch", "iac-hardening-pr", "block-medium-iac-pr", "missing-auto-upgrade", "iac/gcp/k8s-pipelines-bp/module.tf", 105, 1),
				},
				Sast: []violationutils.JasViolation{
					jasFindingFixture("pr-appsec-watch", "sast-low-pr", "block-low-sast-pr", "info-leak", "sast/flask_webgoat/ui.py", 25, 9),
				},
			},
			action:       failActionPr,
			expectedFile: "../../testdata/logfailingrules/fail_pr_results.txt",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issuesFound := collectFailingIssues(tc.violations, tc.action)
			expected, err := os.ReadFile(tc.expectedFile)
			require.NoError(t, err)
			// Normalization for Windows
			expectedText := strings.ReplaceAll(string(expected), "\r\n", "\n")
			assert.Equal(t, expectedText, renderFailingIssues(issuesFound, tc.action))
		})
	}
}

func jasFindingFixture(watch, policy, rule, ruleId, file string, line, column int) violationutils.JasViolation {
	return violationutils.JasViolation{
		Violation: violationutils.Violation{
			Watch:    watch,
			Policies: []violationutils.Policy{{PolicyName: policy, Rule: rule, FailBuild: true, FailPullRequest: true}},
		},
		Rule: sarif.NewReportingDescriptor().WithID(ruleId),
		Location: sarif.NewLocation().WithPhysicalLocation(
			sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewArtifactLocation().WithURI(file)).
				WithRegion(sarif.NewRegion().WithStartLine(line).WithStartColumn(column)),
		),
	}
}
