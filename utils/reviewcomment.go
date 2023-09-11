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
	Location    *sarif.Location
	CommentInfo vcsclient.CommentInfo
	Type        ReviewCommentType
}

type ApplicabilityWithRelatedInfo struct {
	Applicability *sarif.Run
	RelatedInfo   formats.VulnerabilityOrViolationRow
}

const (
	ApplicableComment ReviewCommentType = "Applicable"
	IacComment        ReviewCommentType = "Iac"
	SastComment       ReviewCommentType = "Sast"
)

func AddReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, applicableIssues, iacIssues, sastIssues *sarif.Run) (err error) {
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
	// Add review comments for the given data
	commentsToAdd, err := getNewReviewComments(repo, vulnerabilitiesRows, applicableIssues, iacIssues, sastIssues)
	if err != nil {
		return
	}
	if len(commentsToAdd) > 0 {
		if err = client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, commentsToAdd...); err != nil {
			err = errors.New("couldn't add pull request review comment: " + err.Error())
			return
		}
	}
	return
}

func getFrogbotReviewComments(existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
	for _, comment := range existingComments {
		if strings.Contains(comment.Content, outputwriter.ReviewCommentGeneratedByFrogbot) {
			log.Debug("Deleting comment id:", comment.ID)
			reviewComments = append(reviewComments, comment)
		}
	}
	return
}

func getNewReviewComments(repo *Repository, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, applicableIssues, iacIssues, sastIssues *sarif.Run) (commentsToAdd []vcsclient.PullRequestComment, err error) {
	writer := repo.OutputWriter

	if len(applicableIssues.Results) > 0 {
		attachApplicabilityRelatedInfo(applicableIssues, vulnerabilitiesRows)
		var comments []vcsclient.PullRequestComment
		if comments, err = generateCommentsForType(ApplicableComment, applicableIssues, writer); err != nil {
			return
		}
		commentsToAdd = append(commentsToAdd, comments...)
	}
	if len(iacIssues.Results) > 0 {
		var comments []vcsclient.PullRequestComment
		if comments, err = generateCommentsForType(IacComment, iacIssues, writer); err != nil {
			return
		}
		commentsToAdd = append(commentsToAdd, comments...)
	}
	if len(sastIssues.Results) > 0 {
		var comments []vcsclient.PullRequestComment
		if comments, err = generateCommentsForType(SastComment, sastIssues, writer); err != nil {
			return
		}
		commentsToAdd = append(commentsToAdd, comments...)
	}

	return
}

func generateCommentsForType(commentType ReviewCommentType, data *sarif.Run, writer outputwriter.OutputWriter) (commentsToAdd []vcsclient.PullRequestComment, err error) {
	for _, result := range data.Results {
		for _, location := range result.Locations {
			log.Debug("Adding new review comment", xrayutils.GetLocationFileName(location))
			var rule *sarif.ReportingDescriptor
			if rule, err = data.GetRuleById(*result.RuleID); err != nil {
				return
			}
			commentsToAdd = append(commentsToAdd, generateReviewComment(location, commentType, result, rule, writer))
		}
	}
	return
}

func generateReviewComment(location *sarif.Location, commentType ReviewCommentType, relatedResult *sarif.Result, relatedRule *sarif.ReportingDescriptor, writer outputwriter.OutputWriter) (comment vcsclient.PullRequestComment) {
	return vcsclient.PullRequestComment{
		CommentInfo: vcsclient.CommentInfo{
			Content: generateReviewCommentContent(commentType, location, relatedResult, relatedRule, writer),
		},
		PullRequestDiff: createPullRequestDiff(location),
	}
}

func generateReviewCommentContent(commentType ReviewCommentType, location *sarif.Location, relatedResult *sarif.Result, relatedRule *sarif.ReportingDescriptor, writer outputwriter.OutputWriter) (content string) {
	switch commentType {
	case ApplicableComment:
		applicableCveInfo := getApplicabilityCveInformation(relatedRule)
		content += writer.ApplicableCveReviewContent(
			strings.ToLower(applicableCveInfo.Severity),
			xrayutils.GetResultMsgText(relatedResult),
			*relatedRule.FullDescription.Markdown,
			applicableCveInfo.Summary,
			getCveRemediation(applicableCveInfo),
		)
	case IacComment:
		content += writer.IacReviewContent(
			strings.ToLower(xrayutils.GetResultSeverity(relatedResult)),
			xrayutils.GetResultMsgText(relatedResult),
			*relatedRule.FullDescription.Markdown,
		)
	case SastComment:
		content += writer.SastReviewContent(
			strings.ToLower(xrayutils.GetResultSeverity(relatedResult)),
			xrayutils.GetResultMsgText(relatedResult),
			*relatedRule.FullDescription.Markdown,
			xrayutils.GetLocationRelatedCodeFlowsFromResult(location, relatedResult),
		)
	}

	content += writer.ReviewFooter()
	return
}

func createPullRequestDiff(location *sarif.Location) vcsclient.PullRequestDiff {
	return vcsclient.PullRequestDiff{
		OriginalFilePath:    xrayutils.GetLocationFileName(location),
		OriginalStartLine:   xrayutils.GetLocationStartLine(location),
		OriginalEndLine:     xrayutils.GetLocationEndLine(location),
		OriginalStartColumn: xrayutils.GetLocationStartColumn(location),
		OriginalEndColumn:   xrayutils.GetLocationEndColumn(location),

		NewFilePath:    xrayutils.GetLocationFileName(location),
		NewStartLine:   xrayutils.GetLocationStartLine(location),
		NewEndLine:     xrayutils.GetLocationEndLine(location),
		NewStartColumn: xrayutils.GetLocationStartColumn(location),
		NewEndColumn:   xrayutils.GetLocationEndColumn(location),
	}
}

func attachApplicabilityRelatedInfo(applicability *sarif.Run, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) {
	for _, rule := range applicability.Tool.Driver.Rules {
		setCveInfoToRule(rule, vulnerabilitiesRows)
	}
}

func setCveInfoToRule(rule *sarif.ReportingDescriptor, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow) {
	cve := xrayutils.GetCveIdFromRuleId(rule.ID)
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
