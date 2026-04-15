package utils

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v2/utils/issues"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
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
	SnippetComment    ReviewCommentType = "Snippet"

	snippetVersionMarker   = "snippet"
	commentRemovalErrorMsg = "An error occurred while attempting to remove older Frogbot pull request comments:"
)

// In Scan PR, if there are no issues, comments will be added to the PR with a message that there are no issues.
func HandlePullRequestCommentsAfterScan(issues *issues.ScansIssuesCollection, resultContext results.ResultContext, repo *Repository, client vcsclient.VcsClient, pullRequestID int) (err error) {
	// The removal of comments may fail for various reasons,
	// such as concurrent scanning of pull requests and attempts
	// to delete comments that have already been removed in a different process.
	// Since this task is not mandatory for a Frogbot run,
	// we will not cause a Frogbot run to fail but will instead log the error.
	log.Debug("Looking for an existing Frogbot pull request comment. Deleting it if it exists...")
	if e := DeletePullRequestComments(repo, client, pullRequestID); e != nil {
		log.Error(fmt.Sprintf("%s:\n%v", commentRemovalErrorMsg, e))
	}

	// Add summary scan comment
	if issues.IssuesExists(repo.FrogbotConfig.ShowSecretsAsPrComment) || !repo.FrogbotConfig.HideSuccessBannerForNoIssues {
		for _, comment := range generatePullRequestSummaryComment(*issues, resultContext, repo.FrogbotConfig.ShowSecretsAsPrComment, repo.OutputWriter) {
			if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, comment, pullRequestID); err != nil {
				err = errors.New("couldn't add pull request comment: " + err.Error())
				return
			}
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
	commentsToDelete := getFrogbotComments(comments)
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

func generatePullRequestSummaryComment(issuesCollection issues.ScansIssuesCollection, resultContext results.ResultContext, includeSecrets bool, writer outputwriter.OutputWriter) []string {
	if !issuesCollection.IssuesExists(includeSecrets) {
		return outputwriter.GetMainCommentContent([]string{}, false, true, writer)
	}
	// Summary
	content := []string{outputwriter.ScanSummaryContent(issuesCollection, resultContext, includeSecrets, writer)}
	// Violations
	if violationsContent := outputwriter.PolicyViolationsContent(issuesCollection, writer); len(violationsContent) > 0 {
		content = append(content, violationsContent...)
	}
	// Vulnerabilities
	if vulnerabilitiesContent := outputwriter.GetVulnerabilitiesContent(issuesCollection.ScaVulnerabilities, writer); len(vulnerabilitiesContent) > 0 {
		content = append(content, vulnerabilitiesContent...)
	}
	return outputwriter.GetMainCommentContent(content, true, true, writer)
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
			if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, outputwriter.GetFallbackReviewCommentContent(comment.CommentInfo.Content, comment.Location), pullRequestID); err != nil {
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
		if err = client.DeletePullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, getFrogbotComments(existingComments)...); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}
	return
}

func getFrogbotComments(existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
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

	commentsToAdd = append(commentsToAdd, generateSnippetReviewComment(issues, writer)...)

	// CVE Applicable Evidence review comments
	for _, applicableEvidences := range issues.GetApplicableEvidences() {
		commentsToAdd = append(commentsToAdd, generateReviewComment(ApplicableComment, applicableEvidences.Evidence.Location, generateApplicabilityReviewContent(applicableEvidences, writer)))
	}
	// IAC review comments
	for _, iac := range issues.IacVulnerabilities {
		commentsToAdd = append(commentsToAdd, generateReviewComment(IacComment, iac.Location, generateSourceCodeReviewContent(IacComment, false, writer, iac)))
	}
	for _, similarIacIssues := range groupSimilarJasIssues(issues.IacViolations) {
		commentsToAdd = append(commentsToAdd, generateReviewComment(IacComment, similarIacIssues.Location, generateSourceCodeReviewContent(IacComment, true, writer, similarIacIssues.issues...)))
	}
	// SAST review comments
	for _, sast := range issues.SastVulnerabilities {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SastComment, sast.Location, generateSourceCodeReviewContent(SastComment, false, writer, sast)))
	}
	if len(issues.SastViolations) > 0 {
		for _, similarSastIssues := range groupSimilarJasIssues(issues.SastViolations) {
			commentsToAdd = append(commentsToAdd, generateReviewComment(SastComment, similarSastIssues.Location, generateSourceCodeReviewContent(SastComment, true, writer, similarSastIssues.issues...)))
		}
	}

	// Secrets review comments
	if !repo.FrogbotConfig.ShowSecretsAsPrComment {
		return
	}
	for _, secret := range issues.SecretsVulnerabilities {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SecretComment, secret.Location, generateSourceCodeReviewContent(SecretComment, false, writer, secret)))
	}
	if len(issues.SecretsViolations) > 0 {
		for _, similarSecretsIssues := range groupSimilarJasIssues(issues.SecretsViolations) {
			commentsToAdd = append(commentsToAdd, generateReviewComment(SecretComment, similarSecretsIssues.Location, generateSourceCodeReviewContent(SecretComment, true, writer, similarSecretsIssues.issues...)))
		}
	}

	return
}

func generateSnippetReviewComment(issues *issues.ScansIssuesCollection, writer outputwriter.OutputWriter) (commentsToAdd []ReviewComment) {
	type key struct {
		File string
		Line int
	}

	locToOrigin := make(map[key]*datastructures.Set[string])
	licensesBySnippet := make(map[key][]formats.LicenseViolationRow)
	for _, lic := range issues.LicensesViolations {
		if lic.ImpactedDependencyVersion != snippetVersionMarker {
			continue
		}
		// Extract license violation information that are related to a snippet
		for _, ipath := range lic.ImpactPaths {
			if len(ipath) == 0 {
				continue
			}

			// Leaf node of the impact path is the snippet location
			snippet := ipath[len(ipath)-1]

			// Map evidence to snippet location
			for _, evidence := range snippet.Evidences {
				k := key{File: evidence.File, Line: evidence.StartLine}
				licensesBySnippet[k] = append(licensesBySnippet[k], lic)
				if locToOrigin[k] == nil {
					locToOrigin[k] = datastructures.MakeSet[string]()
				}
				locToOrigin[k].AddElements(evidence.ExternalReferences...)
			}
		}
	}
	// Sort snippet locations by file and line
	sortedKeys := make([]key, 0, len(licensesBySnippet))
	for k := range licensesBySnippet {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		if sortedKeys[i].File != sortedKeys[j].File {
			return sortedKeys[i].File < sortedKeys[j].File
		}
		return sortedKeys[i].Line < sortedKeys[j].Line
	})
	// Generate review comments for each snippet location
	for _, loc := range sortedKeys {
		licenses := licensesBySnippet[loc]
		refSlice := locToOrigin[loc].ToSlice()
		commentsToAdd = append(commentsToAdd, generateReviewComment(
			SnippetComment,
			formats.Location{
				File:      loc.File,
				StartLine: loc.Line,
				EndLine:   loc.Line + snippetLineDeltaFromRef(refSlice),
			},
			generateComponentReviewContent(
				SnippetComment,
				true,
				writer,
				licenses,
				refSlice),
		))
	}
	return
}

var snippetLineRangeRe = regexp.MustCompile(`#L(\d+)-L(\d+)$`)

const defaultSnippetLineDelta = 20

// snippetLineDeltaFromRef parses a GitHub-style line range fragment (#L<start>-L<end>)
// from the first matching external reference URL and returns end−start (the delta to
// add to a start line to compute the end line).
// Falls back to defaultSnippetLineDelta when no URL contains a parseable range.
func snippetLineDeltaFromRef(refs []string) int {
	for _, ref := range refs {
		m := snippetLineRangeRe.FindStringSubmatch(ref)
		if len(m) != 3 {
			continue
		}
		start, err1 := strconv.Atoi(m[1])
		end, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		return end - start
	}
	return defaultSnippetLineDelta
}

type jasCommentIssues struct {
	// The location of the issue that the comment will be added to.
	formats.Location
	// Similar issues at the same location that will be shown in the same comment.
	issues []formats.SourceCodeRow
}

// For JAS violations we can have similar issues at the same location, we need to group similar issues to add them to the same comment based on `getSourceCodeRowId`.
func groupSimilarJasIssues(issues []formats.SourceCodeRow) (groupedIssues []jasCommentIssues) {
	idToIssues := make(map[string]jasCommentIssues)
	for _, issue := range issues {
		id := getSourceCodeRowId(issue)
		if similarIssue, ok := idToIssues[id]; ok {
			similarIssue.issues = append(similarIssue.issues, issue)
			idToIssues[id] = similarIssue
			continue
		}
		idToIssues[id] = jasCommentIssues{
			Location: issue.Location,
			issues:   []formats.SourceCodeRow{issue},
		}
	}
	for _, similarIssue := range idToIssues {
		groupedIssues = append(groupedIssues, similarIssue)
	}
	return
}

// Similar comment should have the same location and rule-id.
func getSourceCodeRowId(issue formats.SourceCodeRow) string {
	return issue.RuleId + issue.Location.ToString()
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

func generateApplicabilityReviewContent(issue issues.ApplicableEvidences, writer outputwriter.OutputWriter) string {
	return outputwriter.GenerateReviewCommentContent(outputwriter.ApplicableCveReviewContent(issue, writer), writer)
}

func generateSourceCodeReviewContent(commentType ReviewCommentType, violation bool, writer outputwriter.OutputWriter, similarIssues ...formats.SourceCodeRow) (content string) {
	switch commentType {
	case IacComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent(violation, writer, similarIssues...), writer)
	case SastComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SastReviewContent(violation, writer, similarIssues...), writer)
	case SecretComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SecretReviewContent(violation, writer, similarIssues...), writer)
	}
	return
}

func generateComponentReviewContent(
	commentType ReviewCommentType,
	violation bool,
	writer outputwriter.OutputWriter,
	licenses []formats.LicenseViolationRow,
	externalReferences []string,
) (content string) {
	if commentType == SnippetComment {
		return outputwriter.GenerateReviewCommentContent(outputwriter.SnippetReviewContent(
			violation,
			writer,
			licenses,
			externalReferences,
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
