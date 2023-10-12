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
	CommentInfo vcsclient.PullRequestComment
	Type        ReviewCommentType
}

const (
	ApplicableComment ReviewCommentType = "Applicable"
	IacComment        ReviewCommentType = "Iac"
	SastComment       ReviewCommentType = "Sast"
)

func HandlePullRequestCommentsAfterScan(issues *IssuesCollection, repo *Repository, client vcsclient.VcsClient, pullRequestID int) (err error) {
	if !repo.Params.AvoidPreviousPrCommentsDeletion {
		log.Debug("Looking for an existing Frogbot pull request comment. Deleting it if it exists...")
		// Delete previous PR regular comments, if exists (not related to location of a change)
		if err = DeleteExistingPullRequestComments(repo, client); err != nil {
			err = errors.New("couldn't delete pull request comment: " + err.Error())
			return
		}
		// Delete previous PR review comments, if exists (related to location of a change)
		if err = DeleteExistingPullRequestReviewComments(repo, pullRequestID, client); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}

	// Add summary (SCA, license) scan comment
	if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, createPullRequestComment(issues, repo.OutputWriter), pullRequestID); err != nil {
		err = errors.New("couldn't add pull request comment: " + err.Error())
		return
	}
	// Handle review comments at the pull request
	if err = addReviewComments(repo, pullRequestID, client, issues); err != nil {
		err = errors.New("couldn't add review comments: " + err.Error())
		return
	}
	return
}

// Delete existing pull request regular comments (Summary, Fallback review comments)
func DeleteExistingPullRequestComments(repository *Repository, client vcsclient.VcsClient) error {
	prDetails := repository.PullRequestDetails
	comments, err := GetSortedPullRequestComments(client, prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID))
	if err != nil {
		return fmt.Errorf(
			"failed to get comments. the following details were used in order to fetch the comments: <%s/%s> pull request #%d. the error received: %s",
			repository.RepoOwner, repository.RepoName, int(repository.PullRequestDetails.ID), err.Error())
	}
	// Previous Fallback review comments
	commentsToDelete := getFrogbotReviewComments(comments)
	// Previous Summary comments
	for _, comment := range comments {
		if repository.OutputWriter.IsFrogbotResultComment(comment.Content) {
			commentsToDelete = append(commentsToDelete, comment)
		}
	}
	// Delete
	if len(commentsToDelete) > 0 {
		for _, commentToDelete := range commentsToDelete {
			if err = client.DeletePullRequestComment(context.Background(), prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID), int(commentToDelete.ID)); err != nil {
				return err
			}
		}
	}
	return err
}

func createPullRequestComment(issues *IssuesCollection, writer outputwriter.OutputWriter) string {
	if !issues.IssuesExists() {
		return writer.NoVulnerabilitiesTitle() + writer.UntitledForJasMsg() + writer.Footer()
	}
	comment := strings.Builder{}
	comment.WriteString(writer.VulnerabilitiesTitle(true))
	comment.WriteString(writer.VulnerabilitiesContent(issues.Vulnerabilities))
	comment.WriteString(writer.LicensesContent(issues.Licenses))
	comment.WriteString(writer.UntitledForJasMsg())
	comment.WriteString(writer.Footer())

	return comment.String()
}

func addReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, issues *IssuesCollection) (err error) {
	commentsToAdd := getNewReviewComments(repo, issues)
	if len(commentsToAdd) == 0 {
		return
	}
	// Add review comments for the given data
	for _, comment := range commentsToAdd {
		log.Debug("creating a review comment for", comment.Type, comment.Location.File, comment.Location.StartLine, comment.Location.StartColumn)
		if e := client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, comment.CommentInfo); e != nil {
			log.Debug("couldn't add pull request review comment, fallback to regular comment: " + e.Error())
			if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, getRegularCommentContent(comment), pullRequestID); err != nil {
				err = errors.New("couldn't add pull request  comment, fallback to comment: " + err.Error())
				return
			}
		}
	}
	return
}

// Delete existing pull request review comments (Applicable, Sast, Iac)
func DeleteExistingPullRequestReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient) (err error) {
	// Get all review comments in PR
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

func getFrogbotReviewComments(existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
	for _, comment := range existingComments {
		if strings.Contains(comment.Content, outputwriter.ReviewCommentId) {
			log.Debug("Deleting comment id:", comment.ID)
			reviewComments = append(reviewComments, comment)
		}
	}
	return
}

func getRegularCommentContent(comment ReviewComment) string {
	return outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + outputwriter.GetLocationDescription(comment.Location) + comment.CommentInfo.Content
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
		return outputwriter.GenerateReviewCommentContent(writer.IacReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
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
