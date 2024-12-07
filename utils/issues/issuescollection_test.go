package issues

import (
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/stretchr/testify/assert"
)

func TestCountIssuesCollectionFindings(t *testing.T) {
	issuesCollection := ScansIssuesCollection{
		ScaVulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					Components: []formats.ComponentRow{
						{
							Name:    "vuln-pack-name1",
							Version: "1.0.0",
						},
						{
							Name:    "vuln-pack-name1",
							Version: "1.2.3",
						},
						{
							Name:    "vuln-pack-name2",
							Version: "1.2.3",
						},
					},
				},
				IssueId: "Xray-Id",
			},
			{
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					Components: []formats.ComponentRow{
						{
							Name:    "vuln-pack-name3",
							Version: "1.0.0",
						},
					},
				},
				IssueId: "Xray-Id2",
			},
		},

		IacVulnerabilities: []formats.SourceCodeRow{
			{
				ScannerDescription: "Iac issue",
			},
		},
		SecretsVulnerabilities: []formats.SourceCodeRow{
			{
				ScannerDescription: "Secret issue",
			},
		},
		SecretsViolations: []formats.SourceCodeRow{
			{
				ScannerDescription: "Secret violation",
			},
		},
		SastVulnerabilities: []formats.SourceCodeRow{
			{
				ScannerDescription: "Sast issue1",
			},
			{
				ScannerDescription: "Sast issue2",
			},
		},
	}

	// With Secrets
	findingsAmount := issuesCollection.GetTotalIssues(true)
	assert.Equal(t, 9, findingsAmount)
	// No Secrets
	findingsAmount = issuesCollection.GetTotalIssues(false)
	assert.Equal(t, 7, findingsAmount)
}
