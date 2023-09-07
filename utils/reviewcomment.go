package utils

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/datastructures"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

type ReviewCommentType string

type FrogbotReviewComment struct {
	CommentInfo vcsclient.CommentInfo
	Type ReviewCommentType
	Location *sarif.Location
}

// Define a regular expression pattern to match the Markdown comment
const (
	ApplicableComment = "Applicable"
	IacComment = "Iac"
	SastComment = "Sast"

	idSearchPattern = `\[comment\]: <> \((.*?)\)`
	// ID Pattern input: Type_StartLine_StartCol_EndLine_EndCol_Snippet_File
	reviewIdPattern = "FrogbotReview_%s_%s_%s_%s_%s_%s_%s"
)

var idRegex = regexp.MustCompile(idSearchPattern)

func UpdateReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, applicableIssues, iacIssues, sastIssues *sarif.Run) (err error) {
	var commentsToDelete []vcsclient.CommentInfo
	var commentsToAdd []vcsclient.PullRequestComment
	// Calculate changes to review comments
	if commentsToDelete, commentsToAdd, err = getCommentsToUpdate(repo, pullRequestID, client, applicableIssues, iacIssues, sastIssues); err != nil {
		return
	}
	// Delete old (fixed) review comments
	for _, commentToDelete := range commentsToDelete {
		if err = client.DeletePullRequestReviewComment(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, &commentToDelete); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}
	// Add new (discovered) review comments
	if err = client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, commentsToAdd...); err != nil {
		err = errors.New("couldn't add pull request review comment: " + err.Error())
		return
	}
	return
}

func getCommentsToUpdate(repo *Repository, pullRequestID int, client vcsclient.VcsClient, applicableIssues, iacIssues, sastIssues *sarif.Run) (commentsToDelete []vcsclient.CommentInfo, commentsToAdd []vcsclient.PullRequestComment, err error) {
	var existingComments []vcsclient.CommentInfo
	if existingComments, err =  client.ListPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID); err != nil {
		err = errors.New("couldn't list existing review comments: " + err.Error())
		return
	}
	existingApplicableComments, existingIacComments, existingSastComments := convertCommentsToFrogbotReviewComments(existingComments)
	
	// Get comments related to updates on applicable review
	applicableToDelete, applicableToAdd := extractReviewChanges(ApplicableComment, applicableIssues, existingApplicableComments)
	commentsToAdd = append(commentsToAdd, applicableToAdd...)
	commentsToDelete = append(commentsToDelete, applicableToDelete...)

	// Get comments related to updates on Iac review
	iacToDelete, iacToAdd := extractReviewChanges(IacComment, iacIssues, existingIacComments)
	commentsToAdd = append(commentsToAdd, iacToAdd...)
	commentsToDelete = append(commentsToDelete, iacToDelete...)

	// Get comments related to updates on applicable review
	sastToDelete, sastToAdd := extractReviewChanges(SastComment, sastIssues, existingSastComments)
	commentsToAdd = append(commentsToAdd, sastToAdd...)
	commentsToDelete = append(commentsToDelete, sastToDelete...)

	return
}

func convertCommentsToFrogbotReviewComments(comments []vcsclient.CommentInfo) (applicableComments map[string]FrogbotReviewComment, iacComments map[string]FrogbotReviewComment, sastComments map[string]FrogbotReviewComment) {
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
	return
}


func convertToFrogbotReviewComment(comment vcsclient.CommentInfo) (*FrogbotReviewComment, string) {
	id, ok := extractFrogbotReviewCommentId(comment)
	if !ok {
		return nil, ""
	}
	scanType, location, ok := extractInfoFromId(id)
	if !ok {
		return nil, ""
	}
	return &FrogbotReviewComment{CommentInfo: comment, Type: scanType, Location: location}, id
}

func extractFrogbotReviewCommentId(comment vcsclient.CommentInfo) (string, bool) {
	match := idRegex.FindStringSubmatch(comment.Content)
	if len(match) >= 2 {
		return match[1], true
	}
	return "", false
}

func extractInfoFromId(id string) (commentType ReviewCommentType, location *sarif.Location, ok bool) {
	// Extract comment type
    switch "" {
    case string(ApplicableComment):
        commentType = ApplicableComment
    case string(IacComment):
        commentType = IacComment
    case string(SastComment):
        commentType = SastComment
    default:
        return "", nil, false
    }
	// Extract comment location
	location = sarif.NewLocation()
	ok = true
	return
}

// ID Pattern input: Type_StartLine_StartCol_EndLine_EndCol_Snippet_File
func generateFrogbotReviewCommentId(commentType ReviewCommentType, location *sarif.Location) string {
	id := fmt.Sprintf(reviewIdPattern, 
		commentType, 
		xrayutils.GetLocationStartLine(location), 
		xrayutils.GetLocationStartColumn(location), 
		xrayutils.GetLocationEndLine(location), 
		xrayutils.GetLocationEndColumn(location), 
		xrayutils.GetLocationSnippet(location), 
		xrayutils.GetLocationFileName(location),
	)
	return outputwriter.MarkdownComment(id)
}

func extractReviewChanges(commentType ReviewCommentType, data *sarif.Run, existingFrogbotComments map[string]FrogbotReviewComment) (commentsToDelete []vcsclient.CommentInfo, commentsToAdd []vcsclient.PullRequestComment) {
	// Go over the data run results and generate new comments if not exists yet


	// All the comments that are left are comments not in the current data = fixed and should be removed.
	for _, fixedComment := range existingFrogbotComments {
		commentsToDelete = append(commentsToDelete, fixedComment.CommentInfo)
	}
	return
}