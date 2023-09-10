package utils

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type ReviewCommentType string

type FrogbotReviewComment struct {
	CommentInfo vcsclient.CommentInfo
	Type        ReviewCommentType
	Location    *sarif.Location
}

type ApplicabilityWithRelatedInfo struct {
	Applicability *sarif.Run
	RelatedInfo   formats.VulnerabilityOrViolationRow
}

const (
	ApplicableComment ReviewCommentType = "Applicable"
	IacComment        ReviewCommentType = "Iac"
	SastComment       ReviewCommentType = "Sast"

	// Comments returns from vcs API with content only.
	// We mark our comments with ID constructed with the relevant MetaData on it so we can fetch and parse it later
	// Define a regular expression pattern to match the Markdown comment
	idSearchPattern = `\[comment\]: <> \((.*?)\)`
	// ID Pattern format: Type StartLine StartCol EndLine EndCol Snippet File
	reviewCommentIdFormat = "FrogbotReview %s %d %d %d %d %s %s"
)

var commentIdRegex = regexp.MustCompile(idSearchPattern)

func generateFrogbotReviewCommentId(commentType ReviewCommentType, location *sarif.Location) string {
	id := fmt.Sprintf(reviewCommentIdFormat,
		commentType,
		xrayutils.GetLocationStartLine(location),
		xrayutils.GetLocationStartColumn(location),
		xrayutils.GetLocationEndLine(location),
		xrayutils.GetLocationEndColumn(location),
		xrayutils.GetLocationSnippet(location),
		xrayutils.GetLocationFileName(location),
	)
	return id
}

func convertToFrogbotReviewComment(comment vcsclient.CommentInfo) (*FrogbotReviewComment, string) {
	id, isFrogbotReviewComment := extractFrogbotReviewCommentId(comment)
	if !isFrogbotReviewComment {
		return nil, ""
	}
	scanType, location, isFrogbotReviewComment := extractInfoFromId(id)
	if !isFrogbotReviewComment {
		return nil, ""
	}
	return &FrogbotReviewComment{CommentInfo: comment, Type: scanType, Location: location}, id
}

func extractFrogbotReviewCommentId(comment vcsclient.CommentInfo) (string, bool) {
	match := commentIdRegex.FindStringSubmatch(comment.Content)
	if len(match) >= 2 {
		return match[1], true
	}
	return "", false
}

func extractInfoFromId(id string) (commentType ReviewCommentType, location *sarif.Location, extracted bool) {
	// Try to parse string id to values
	typeValue, startLineValue, startColValue, endLineValue, endColValue, snippetValue, fileValue, err := parseIdToValues(id)
	if err != nil {
		return
	}
	// Try to extract comment type
	if commentType, extracted = convertToReviewCommentType(typeValue); !extracted {
		return
	}
	// Create comment location
	location = sarif.NewLocation().WithPhysicalLocation(
		sarif.NewPhysicalLocation().WithArtifactLocation(sarif.NewArtifactLocation().WithUri(fileValue)).WithRegion(
			sarif.NewRegion().
				WithStartLine(startLineValue).
				WithStartColumn(startColValue).
				WithEndLine(endLineValue).
				WithEndColumn(endColValue).
				WithSnippet(sarif.NewArtifactContent().WithText(snippetValue)),
		),
	)
	return
}

func parseIdToValues(id string) (typeValue string, startLineValue, startColValue, endLineValue, endColValue int, snippetValue, fileValue string, err error) {
	var startLineStrValue, startColStrValue, endLineStrValue, endColStrValue string
	if _, err = fmt.Sscanf(id, reviewCommentIdFormat,
		&typeValue,
		&startLineStrValue,
		&startColStrValue,
		&endLineStrValue,
		&endColStrValue,
		&snippetValue,
		&fileValue,
	); err != nil {
		return
	}
	if startLineValue, err = strconv.Atoi(startLineStrValue); err != nil {
		return
	}
	if startColValue, err = strconv.Atoi(startColStrValue); err != nil {
		return
	}
	if endLineValue, err = strconv.Atoi(endLineStrValue); err != nil {
		return
	}
	endColValue, err = strconv.Atoi(endColStrValue)
	return
}

func convertToReviewCommentType(typeValue string) (commentType ReviewCommentType, converted bool) {
	converted = true
	switch typeValue {
	case string(ApplicableComment):
		commentType = ApplicableComment
	case string(IacComment):
		commentType = IacComment
	case string(SastComment):
		commentType = SastComment
	default:
		converted = false
	}
	return
}

func UpdateReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, applicableIssues, iacIssues, sastIssues *sarif.Run) (err error) {
	var commentsToDelete []vcsclient.CommentInfo
	var commentsToAdd []vcsclient.PullRequestComment
	// Calculate changes to review comments
	if commentsToDelete, commentsToAdd, err = getCommentsToUpdate(repo, pullRequestID, client, vulnerabilitiesRows, applicableIssues, iacIssues, sastIssues); err != nil {
		err = errors.New("couldn't calculate updates on review comments: " + err.Error())
		return
	}
	if repo.IncludeAllVulnerabilities && len(commentsToDelete) > 0 {
		// If the given data includes all vulnerabilities we can tell what was fixed and delete old (fixed) review comments
		if err = client.DeletePullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, commentsToDelete...); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}
	// Add new (discovered) review comments
	if len(commentsToAdd) > 0 {
		if err = client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, commentsToAdd...); err != nil {
			err = errors.New("couldn't add pull request review comment: " + err.Error())
			return
		}
	}
	return
}

func getCommentsToUpdate(repo *Repository, pullRequestID int, client vcsclient.VcsClient, vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, applicableIssues, iacIssues, sastIssues *sarif.Run) (commentsToDelete []vcsclient.CommentInfo, commentsToAdd []vcsclient.PullRequestComment, err error) {
	var existingComments []vcsclient.CommentInfo
	if existingComments, err = client.ListPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID); err != nil {
		err = errors.New("couldn't list existing review comments: " + err.Error())
		return
	}
	existingApplicableComments, existingIacComments, existingSastComments := extractFrogbotReviewComments(existingComments)
	writer := repo.OutputWriter

	// Get comments related to updates on applicable review
	attachApplicabilityRelatedInfo(applicableIssues, vulnerabilitiesRows)
	applicableToDelete, applicableToAdd, err := extractRunReviewChanges(ApplicableComment, applicableIssues, existingApplicableComments, writer)
	if err != nil {
		return
	}
	commentsToAdd = append(commentsToAdd, applicableToAdd...)
	commentsToDelete = append(commentsToDelete, applicableToDelete...)

	// Get comments related to updates on Iac review
	iacToDelete, iacToAdd, err := extractRunReviewChanges(IacComment, iacIssues, existingIacComments, writer)
	if err != nil {
		return
	}
	commentsToAdd = append(commentsToAdd, iacToAdd...)
	commentsToDelete = append(commentsToDelete, iacToDelete...)

	// Get comments related to updates on applicable review
	sastToDelete, sastToAdd, err := extractRunReviewChanges(SastComment, sastIssues, existingSastComments, writer)
	if err != nil {
		return
	}
	commentsToAdd = append(commentsToAdd, sastToAdd...)
	commentsToDelete = append(commentsToDelete, sastToDelete...)

	return
}

func extractFrogbotReviewComments(comments []vcsclient.CommentInfo) (map[string]FrogbotReviewComment, map[string]FrogbotReviewComment, map[string]FrogbotReviewComment) {
	applicableComments := map[string]FrogbotReviewComment{}
	iacComments := map[string]FrogbotReviewComment{}
	sastComments := map[string]FrogbotReviewComment{}

	for _, comment := range comments {
		frogbotComment, id := convertToFrogbotReviewComment(comment)
		if frogbotComment == nil {
			// Not a review comment from Frogbot
			continue
		}
		switch frogbotComment.Type {
		case ApplicableComment:
			applicableComments[id] = *frogbotComment
		case IacComment:
			iacComments[id] = *frogbotComment
		case SastComment:
			sastComments[id] = *frogbotComment
		}
	}
	return applicableComments, iacComments, sastComments
}

func extractRunReviewChanges(commentType ReviewCommentType, data *sarif.Run, existingCommentsForType map[string]FrogbotReviewComment, writer outputwriter.OutputWriter) (commentsToDelete []vcsclient.CommentInfo, commentsToAdd []vcsclient.PullRequestComment, err error) {
	// Go over the data run results and generate new comments if not exists yet
	for _, result := range data.Results {
		for _, location := range result.Locations {
			id := generateFrogbotReviewCommentId(commentType, location)
			if _, exists := existingCommentsForType[id]; exists {
				// Location review comment for this type exist already and not changed
				delete(existingCommentsForType, id)
			} else {
				log.Debug("Adding new review comment", id)
				var rule *sarif.ReportingDescriptor
				if rule, err = data.GetRuleById(*result.RuleID); err != nil {
					return
				}
				commentsToAdd = append(commentsToAdd, generateReviewComment(id, location, commentType, result, rule, writer))
			}
		}
	}
	// All the comments that are left are comments not in the current data = fixed and should be removed.
	for id, fixedComment := range existingCommentsForType {
		log.Debug("Removing fixed review comment", id)
		commentsToDelete = append(commentsToDelete, fixedComment.CommentInfo)
	}
	return
}

func generateReviewComment(id string, location *sarif.Location, commentType ReviewCommentType, relatedResult *sarif.Result, relatedRule *sarif.ReportingDescriptor, writer outputwriter.OutputWriter) (comment vcsclient.PullRequestComment) {
	return vcsclient.PullRequestComment{
		CommentInfo: vcsclient.CommentInfo{
			Content: generateReviewCommentContent(id, commentType, location, relatedResult, relatedRule, writer),
		},
		PullRequestDiff: createPullRequestDiff(location),
	}
}

func generateReviewCommentContent(id string, commentType ReviewCommentType, location *sarif.Location, relatedResult *sarif.Result, relatedRule *sarif.ReportingDescriptor, writer outputwriter.OutputWriter) (content string) {
	content = outputwriter.MarkdownComment(id)

	switch commentType {
	case ApplicableComment:
		applicableCveInfo := getApplicabilityCveInformation(relatedRule)
		content += writer.ApplicableCveReviewContent(
			strings.ToLower(applicableCveInfo.Severity),
			xrayutils.GetResultMsgText(relatedResult),
			*relatedRule.FullDescription.Markdown,
			applicableCveInfo.Summary,
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

	content += outputwriter.ReviewCommentGeneratedByFrogbot
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
		if information, exist := relatedRule.Properties["cve-severity"]; exist {
			if vRow, ok := information.(formats.VulnerabilityOrViolationRow); ok {
				return vRow
			} else {
				return formats.VulnerabilityOrViolationRow{}
			}
		}
	}
	return formats.VulnerabilityOrViolationRow{}
}
