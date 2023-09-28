package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type ReviewCommentType string

type ReviewComment struct {
	Location    formats.Location
	Type        ReviewCommentType
	CommentInfo vcsclient.PullRequestComment
}

const (
	ApplicableComment ReviewCommentType = "Applicable"
	IacComment        ReviewCommentType = "Iac"
	SastComment       ReviewCommentType = "Sast"
)

func AddReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, issues *IssuesCollection) (err error) {
	if err = deleteOldReviewComments(repo, pullRequestID, client); err != nil {
		err = errors.New("couldn't delete pull request review comment: " + err.Error())
		return
	}
	if err = deleteOldFallbackComments(repo, pullRequestID, client); err != nil {
		err = errors.New("couldn't delete pull request comment: " + err.Error())
		return
	}
	commentsToAdd := getNewReviewComments(repo, issues)
	if len(commentsToAdd) == 0 {
		return
	}
	// Add review comments for the given data
	for _, comment := range commentsToAdd {
		log.Debug("creating a review comment for", comment.Type, comment.Location.File, comment.Location.StartLine, comment.Location.StartColumn)
		if e := client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, comment.CommentInfo); e != nil {
			log.Debug("couldn't add pull request review comment, fallback to regular comment: " + e.Error())
			if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, outputwriter.GetFallbackReviewCommentContent(comment.CommentInfo.Content, comment.Location, repo.OutputWriter), pullRequestID); err != nil {
				err = errors.New("couldn't add pull request  comment, fallback to comment: " + err.Error())
				return
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
				err = errors.New("couldn't delete pull request regular comment: " + err.Error())
				return
			}
		}
	}
	return
}

func getFrogbotReviewComments(existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
	for _, comment := range existingComments {
		if strings.Contains(comment.Content, outputwriter.ReviewCommentId) {
			log.Debug("Deleting comment id:", comment.ID)
			reviewComments = append(reviewComments, comment)
		}
	}
	return
}

func getNewReviewComments(repo *Repository, issues *IssuesCollection) (commentsToAdd []ReviewComment) {
	writer := repo.OutputWriter

	for _, vulnerability := range issues.Vulnerabilities {
		for _, cve := range vulnerability.Cves {
			if cve.Applicability != nil {
				for _, evidence := range cve.Applicability.Evidence {
					commentsToAdd = append(commentsToAdd, generateReviewComment(ApplicableComment, evidence.Location, generateApplicabilityReviewContent(evidence, cve, vulnerability, writer)))
				}
			}
		}
	}
	for _, iac := range issues.Iacs {
		commentsToAdd = append(commentsToAdd, generateReviewComment(IacComment, iac.Location, generateSourceCodeReviewContent(IacComment, iac, writer)))
	}
	for _, sast := range issues.Sast {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SastComment, sast.Location, generateSourceCodeReviewContent(SastComment, sast, writer)))
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

func generateApplicabilityReviewContent(issue formats.Evidence, relatedCve formats.CveRow, relatedVulnerability formats.VulnerabilityOrViolationRow, writer outputwriter.OutputWriter) string {
	remediation := ""
	if relatedVulnerability.JfrogResearchInformation != nil {
		remediation = relatedVulnerability.JfrogResearchInformation.Remediation
	}
	return outputwriter.GenerateReviewCommentContent(writer.ApplicableCveReviewContent(
		relatedVulnerability.Severity,
		issue.Reason,
		relatedCve.Applicability.ScannerDescription,
		relatedCve.Id,
		relatedVulnerability.Summary,
		fmt.Sprintf("%s:%s", relatedVulnerability.ImpactedDependencyName, relatedVulnerability.ImpactedDependencyVersion),
		remediation,
	), writer)
}

func generateSourceCodeReviewContent(commentType ReviewCommentType, issue formats.SourceCodeRow, writer outputwriter.OutputWriter) (content string) {
	switch commentType {
	case IacComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
			writer,
		), writer)
	case SastComment:
		return outputwriter.GenerateReviewCommentContent(writer.SastReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
			issue.CodeFlow,
		), writer)
	}
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
