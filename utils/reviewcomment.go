package utils

import (
	"context"
	"errors"
	"strings"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type ReviewCommentType string

type ReviewComment struct {
	Location    formats.Location
	CommentInfo vcsclient.PullRequestComment
	Type        ReviewCommentType
}

const (
	ApplicableComment ReviewCommentType = "Applicable"
	IacComment        ReviewCommentType = "Iac"
	SastComment       ReviewCommentType = "Sast"

	CommentId = "FrogbotReviewComment"
)

func AddReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, iacIssues, sastIssues []formats.SourceCodeRow) (err error) {
	if err = deleteOldReviewComments(repo, pullRequestID, client); err != nil {
		err = errors.New("couldn't delete pull request review comment: " + err.Error())
		return
	}
	if err = deleteOldFallbackComments(repo, pullRequestID, client); err != nil {
		err = errors.New("couldn't delete pull request review comment: " + err.Error())
		return
	}
	// Add review comments for the given data
	commentsToAdd, err := getNewReviewComments(repo, vulnerabilitiesRows, iacIssues, sastIssues)
	if err != nil {
		return
	}
	if len(commentsToAdd) > 0 {
		for _, comment := range commentsToAdd {
			if e := client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, comment.CommentInfo); e != nil {
				log.Debug("couldn't add pull request review comment, fallback to regular comment: " + e.Error())
				if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, getRegularCommentContent(comment), pullRequestID); err != nil {
					err = errors.New("couldn't add pull request  comment, fallback to comment: " + err.Error())
					return
				}
			}
		}
	}
	return
}

func deleteOldReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient) (err error) {
	// Get all comments in PR
	var existingComments []vcsclient.CommentInfo
	if existingComments, err = client.ListPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID); err != nil {
		err = errors.New("couldn't list existing review comments: " + err.Error())
		return
	}
	// Delete old review comments
	if len(existingComments) > 0 {
		if err = client.DeletePullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, getFrogbotReviewComments(existingComments)...); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}
	return
}

func deleteOldFallbackComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient) (err error) {
	// Get all comments in PR
	existingComments, err := GetSortedPullRequestComments(client, repo.RepoOwner, repo.RepoName, pullRequestID)
	if err != nil {
		err = errors.New("couldn't list existing regular comments: " + err.Error())
		return
	}
	// Delete old review comments
	if len(existingComments) > 0 {
		for _, commentToDelete := range getFrogbotReviewComments(existingComments) {
			if err = client.DeletePullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, int(commentToDelete.ID)); err != nil {
				err = errors.New("couldn't delete pull request review comment: " + err.Error())
				return
			}
		}
	}
	return
}

func getFrogbotReviewComments(existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
	log.Debug("Delete old Frogbot review comments")
	for _, comment := range existingComments {
		if strings.Contains(comment.Content, outputwriter.ReviewCommentGeneratedByFrogbot) || strings.Contains(comment.Content, CommentId) {
			log.Debug("Deleting comment id:", comment.ID)
			reviewComments = append(reviewComments, comment)
		}
	}
	return
}

func getRegularCommentContent(comment ReviewComment) string {
	content := outputwriter.MarkdownComment(CommentId)
	return content + outputwriter.GetLocationDescription(comment.Location) + comment.CommentInfo.Content
}

func getNewReviewComments(repo *Repository, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, iacIssues, sastIssues []formats.SourceCodeRow) (commentsToAdd []ReviewComment, err error) {
	writer := repo.OutputWriter

	for _, vulnerability := range vulnerabilitiesRows {
		for _, cve := range vulnerability.Cves {
			if cve.Applicability != nil {
				for _, evidence := range cve.Applicability.Evidence {
					commentsToAdd = append(commentsToAdd, generateReviewComment(ApplicableComment, evidence.Location, generateApplicabilityReviewContent(evidence, cve, vulnerability, writer)))
				}
			}
		}
	}

	for _, iac := range iacIssues {
		commentsToAdd = append(commentsToAdd, generateReviewComment(IacComment, iac.Location, generateReviewCommentContent(IacComment, iac, writer)))
	}

	for _, sast := range sastIssues {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SastComment, sast.Location, generateReviewCommentContent(SastComment, sast, writer)))
	}
	return
}

func generateReviewComment(commentType ReviewCommentType, location formats.Location, content string) (comment ReviewComment) {
	return ReviewComment{
		Location: location,
		CommentInfo: vcsclient.PullRequestComment{
			CommentInfo: vcsclient.CommentInfo{
				Content: content,
			},
			PullRequestDiff: createPullRequestDiff(location),
		},
		Type: commentType,
	}

}

func generateApplicabilityReviewContent(issue formats.Evidence, relatedCve formats.CveRow, relatedVulnerability formats.VulnerabilityOrViolationRow, writer outputwriter.OutputWriter) (content string) {
	remediation := ""
	if relatedVulnerability.JfrogResearchInformation != nil {
		remediation = relatedVulnerability.JfrogResearchInformation.Remediation
	}
	content += writer.ApplicableCveReviewContent(
		relatedVulnerability.Severity,
		issue.Reason,
		relatedCve.Applicability.ScannerDescription,
		relatedVulnerability.Summary,
		remediation,
	)
	content += writer.ReviewFooter()
	return
}

func generateReviewCommentContent(commentType ReviewCommentType, issue formats.SourceCodeRow, writer outputwriter.OutputWriter) (content string) {
	switch commentType {
	case IacComment:
		content += writer.IacReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
		)
	case SastComment:
		content += writer.SastReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
			issue.CodeFlow,
		)
	}

	content += writer.ReviewFooter()
	return
}

func createPullRequestDiff(location formats.Location) vcsclient.PullRequestDiff {
	return vcsclient.PullRequestDiff{
		OriginalFilePath:    location.File,
		OriginalStartLine:   location.StartLine,
		OriginalEndLine:     location.EndLine,
		OriginalStartColumn: location.StartColumn,
		OriginalEndColumn:   location.EndColumn,

		NewFilePath:    location.File,
		NewStartLine:   location.StartLine,
		NewEndLine:     location.EndLine,
		NewStartColumn: location.StartColumn,
		NewEndColumn:   location.EndColumn,
	}
}

func attachApplicabilityRelatedInfo(applicability *sarif.Run, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) {
	for _, rule := range applicability.Tool.Driver.Rules {
		setCveInfoToRule(rule, vulnerabilitiesRows)
	}
}

func setCveInfoToRule(rule *sarif.ReportingDescriptor, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) {
	cve := xrayutils.ApplicabilityRuleIdToCve(rule.ID)
	for _, issue := range vulnerabilitiesRows {
		for _, issueCve := range issue.Cves {
			if cve == issueCve.Id {
				rule.Properties["cve-information"] = issue
				return
			}
		}
	}
}

func getApplicabilityCveInformation(relatedRule *sarif.ReportingDescriptor) formats.VulnerabilityOrViolationRow {
	if relatedRule.Properties != nil {
		if information, exist := relatedRule.Properties["cve-information"]; exist {
			if vRow, ok := information.(formats.VulnerabilityOrViolationRow); ok {
				return vRow
			} else {
				return formats.VulnerabilityOrViolationRow{}
			}
		}
	}
	return formats.VulnerabilityOrViolationRow{}
}

func getCveRemediation(info formats.VulnerabilityOrViolationRow) string {
	if info.JfrogResearchInformation != nil {
		return info.JfrogResearchInformation.Remediation
	}
	return ""
}
