package utils

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
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
	SecretComment     ReviewCommentType = "Secrets"

	RescanRequestComment   = "rescan"
	commentRemovalErrorMsg = "An error occurred while attempting to remove older Frogbot pull request comments:"
)

func HandlePullRequestCommentsAfterScan(issues *issues.ScansIssuesCollection, repo *Repository, client vcsclient.VcsClient, pullRequestID int) (err error) {
	if !repo.Params.AvoidPreviousPrCommentsDeletion {
		// The removal of comments may fail for various reasons,
		// such as concurrent scanning of pull requests and attempts
		// to delete comments that have already been removed in a different process.
		// Since this task is not mandatory for a Frogbot run,
		// we will not cause a Frogbot run to fail but will instead log the error.
		log.Debug("Looking for an existing Frogbot pull request comment. Deleting it if it exists...")
		if e := DeletePullRequestComments(repo, client, pullRequestID); e != nil {
			log.Error(fmt.Sprintf("%s:\n%v", commentRemovalErrorMsg, e))
		}
	}

	// Add summary (SCA, license) scan comment
	for _, comment := range generatePullRequestSummaryComment(issues, repo.ViolationContext, repo.PullRequestSecretComments, repo.OutputWriter) {
		if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, comment, pullRequestID); err != nil {
			err = errors.New("couldn't add pull request comment: " + err.Error())
			return
		}
	}

	// Handle review comments at the pull request
	if err = addReviewComments(repo, pullRequestID, client, issues); err != nil {
		err = errors.New("couldn't add pull request review comments: " + err.Error())
		return
	}
	return
}

func DeletePullRequestComments(repo *Repository, client vcsclient.VcsClient, pullRequestID int) (err error) {
	// Delete previous PR regular comments, if exists (not related to location of a change)
	err = DeleteExistingPullRequestComments(repo, client)
	// Delete previous PR review comments, if exists (related to location of a change)
	return errors.Join(err, DeleteExistingPullRequestReviewComments(repo, pullRequestID, client))
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
	commentsToDelete := getFrogbotComments(repository.OutputWriter, comments)
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

func GenerateFixPullRequestDetails(vulnerabilities []formats.VulnerabilityOrViolationRow, writer outputwriter.OutputWriter) (description string, extraComments []string) {
	content := outputwriter.GetMainCommentContent(outputwriter.GetVulnerabilitiesContent(vulnerabilities, writer), true, false, writer)
	if len(content) == 1 {
		// Limit is not reached, use the entire content as the description
		description = content[0]
		return
	}
	// Limit is reached (at least 2 content), use the first as the description and the rest as extra comments
	for i, comment := range content {
		if i == 0 {
			description = comment
		} else {
			extraComments = append(extraComments, comment)
		}
	}
	return
}

func generatePullRequestSummaryComment(issuesCollection *issues.ScansIssuesCollection, violationContext ViolationContext, includeSecrets bool, writer outputwriter.OutputWriter) []string {
	if !issuesCollection.IssuesExists(includeSecrets) {
		// No Issues
		return outputwriter.GetMainCommentContent([]string{}, false, true, writer)
	}
	content := []string{}
	// if violationContext != None {
	content = append(content, outputwriter.ScanSummaryContent(*issuesCollection, string(violationContext), includeSecrets, writer))
	// }
	if violationsContent := outputwriter.PolicyViolationsContent(*issuesCollection, writer); len(violationsContent) > 0 {
		content = append(content, violationsContent...)
	}
	if vulnerabilitiesContent := outputwriter.GetVulnerabilitiesContent(issuesCollection.ScaVulnerabilities, writer); len(vulnerabilitiesContent) > 0 {
		content = append(content, vulnerabilitiesContent...)
	}
	return outputwriter.GetMainCommentContent(content, true, true, writer)
}

func IsFrogbotRescanComment(comment string) bool {
	return strings.Contains(strings.ToLower(comment), RescanRequestComment)
}

func GetSortedPullRequestComments(client vcsclient.VcsClient, repoOwner, repoName string, prID int) ([]vcsclient.CommentInfo, error) {
	pullRequestsComments, err := client.ListPullRequestComments(context.Background(), repoOwner, repoName, prID)
	if err != nil {
		return nil, err
	}
	// Sort the comment according to time created, the newest comment should be the first one.
	sort.Slice(pullRequestsComments, func(i, j int) bool {
		return pullRequestsComments[i].Created.After(pullRequestsComments[j].Created)
	})
	return pullRequestsComments, nil
}

func addReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, issues *issues.ScansIssuesCollection) (err error) {
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
		if err = client.DeletePullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, getFrogbotComments(repo.OutputWriter, existingComments)...); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}
	return
}

func getFrogbotComments(writer outputwriter.OutputWriter, existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
	for _, comment := range existingComments {
		if outputwriter.IsFrogbotComment(comment.Content) {
			log.Debug("Deleting comment id:", comment.ID)
			reviewComments = append(reviewComments, comment)
		}
	}
	return
}

func getNewReviewComments(repo *Repository, issues *issues.ScansIssuesCollection) (commentsToAdd []ReviewComment) {
	writer := repo.OutputWriter
	for _, applicableEvidence := range issues.GetApplicableEvidences() {
		commentsToAdd = append(commentsToAdd, generateReviewComment(ApplicableComment, applicableEvidence.Location, generateApplicabilityReviewContent(applicableEvidence, cve, vulnerability, writer)))
	}
	for _, iac := range issues.IacVulnerabilities {
		commentsToAdd = append(commentsToAdd, generateReviewComment(IacComment, iac.Location, generateSourceCodeVulnerabilityReviewContent(IacComment, iac, writer)))
	}
	for _, iac := range issues.IacViolations {

	}
	for _, sast := range issues.GetUniqueSastIssues() {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SastComment, sast.Location, generateSourceCodeVulnerabilityReviewContent(SastComment, sast, writer)))
	}
	if !repo.Params.PullRequestSecretComments {
		return
	}
	for _, secret := range issues.GetUniqueSecretsIssues() {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SecretComment, secret.Location, generateSourceCodeVulnerabilityReviewContent(SecretComment, secret, writer)))
	}
	for _, secret := range issues.Secrets {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SecretComment, secret.Location, generateSourceCodeReviewContent(SecretComment, secret, writer)))
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
	return outputwriter.GenerateReviewCommentContent(outputwriter.ApplicableCveReviewContent(
		relatedVulnerability.Severity,
		issue.Reason,
		relatedCve.Applicability.ScannerDescription,
		relatedCve.Id,
		relatedVulnerability.Summary,
		fmt.Sprintf("%s:%s", relatedVulnerability.ImpactedDependencyName, relatedVulnerability.ImpactedDependencyVersion),
		remediation,
		writer,
	), writer)
}

func generateSourceCodeVulnerabilityReviewContent(commentType ReviewCommentType, issue formats.SourceCodeRow, writer outputwriter.OutputWriter) (content string) {
	switch commentType {
	case IacComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent(issue, false ,writer), writer)
	case SastComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SastReviewContent(issue, false ,writer), writer)
	case SecretComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SecretReviewContent(issue, false ,writer), writer)
	}
	return
}

func generateSourceCodeViolationReviewContent(commentType ReviewCommentType, issue formats.SourceCodeRow, writer outputwriter.OutputWriter) (content string) {
	switch commentType {
	case IacComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent(issue, true, writer), writer)
	case SastComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SastReviewContent(issue, true, writer), writer)
	case SecretComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SecretReviewContent(issue, true, writer), writer)
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
