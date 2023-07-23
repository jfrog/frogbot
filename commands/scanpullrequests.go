package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
)

var errPullRequestScan = "pull request %d in the %s repository returned the following error: \n%s"

type ScanAllPullRequestsCmd struct {
}

func (cmd ScanAllPullRequestsCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	for _, config := range configAggregator {
		log.Info("Scanning all open pull requests for repository:", config.RepoName)
		log.Info("-----------------------------------------------------------")
		err := scanAllPullRequests(config, client)
		if err != nil {
			return err
		}
	}

	return nil
}

// Scan pull requests as follows:
// a. Retrieve all open pull requests
// b. Find the ones that should be scanned (new PRs or PRs with a 're-scan' comment)
// c. Audit the dependencies of the source and the target branches.
// d. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
func scanAllPullRequests(repo utils.Repository, client vcsclient.VcsClient) (err error) {
	openPullRequests, err := client.ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName)
	if err != nil {
		return err
	}
	for _, pr := range openPullRequests {
		shouldScan, e := shouldScanPullRequest(repo, client, int(pr.ID))
		if e != nil {
			err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
		}
		if shouldScan {
			spr := &ScanPullRequestCmd{pullRequestDetails: pr}
			e = spr.Run(utils.RepoAggregator{repo}, client)
			// If error, write it in errList and continue to the next PR.
			if e != nil {
				err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
			}
		} else {
			log.Info("Pull Request", pr.ID, "has already been scanned before. If you wish to scan it again, please comment \"rescan\".")
		}
	}
	return
}

func shouldScanPullRequest(repo utils.Repository, client vcsclient.VcsClient, prID int) (shouldScan bool, err error) {
	pullRequestsComments, err := client.ListPullRequestComments(context.Background(), repo.RepoOwner, repo.RepoName, prID)
	if err != nil {
		return
	}
	// Sort the comment according to time created, the newest comment should be the first one.
	sort.Slice(pullRequestsComments, func(i, j int) bool {
		return pullRequestsComments[i].Created.After(pullRequestsComments[j].Created)
	})

	for _, comment := range pullRequestsComments {
		// If this a 're-scan' request comment
		if isFrogbotRescanComment(comment.Content) {
			return true, nil
		}
		// if this is a Frogbot 'scan results' comment and not 're-scan' request comment, do not scan this pull request.
		if repo.OutputWriter.IsFrogbotResultComment(comment.Content) {
			return false, nil
		}
	}
	// This is a new pull request, and it therefore should be scanned.
	return true, nil
}

func isFrogbotRescanComment(comment string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(comment)), utils.RescanRequestComment)
}
