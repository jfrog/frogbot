package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
)

var errPullRequestScan = "pull Request number %d in repository %s returned the following error: \n%s\n"

type ScanAllPullRequestsCmd struct {
	dryRun         bool
	dryRunRepoPath string
}

func (cmd ScanAllPullRequestsCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	var allErrors error
	for index := range configAggregator {
		repository := configAggregator[index]
		log.Info(fmt.Sprintf("Scanning all pull requests for repository: %s", repository.RepoName))
		if e := cmd.scanAllPullRequests(repository, client); e != nil {
			allErrors = errors.Join(allErrors, e)
		}
		// Return the baseWd before continuing to the next repository
		if err = os.Chdir(baseWd); err != nil {
			return err
		}
	}
	return allErrors
}

// Scan pull requests as follows:
// a. Retrieve all open pull requests
// b. Find the ones that should be scanned (new PRs or PRs with a 're-scan' comment)
// c. Audit the dependencies of the source and the target branches.
// d. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
func (cmd ScanAllPullRequestsCmd) scanAllPullRequests(repo utils.Repository, client vcsclient.VcsClient) (aggregatedErrors error) {

	gm, err := utils.InitGitManager(cmd.dryRun, cmd.dryRunRepoPath, &repo.Git)
	if err != nil {
		return err
	}

	openPullRequests, err := client.ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName)
	if err != nil {
		return err
	}

	for index := range openPullRequests {
		currentPr := openPullRequests[index]
		shouldScan, e := shouldScanPullRequest(repo, client, int(currentPr.ID))
		if e != nil {
			aggregatedErrors = errors.Join(aggregatedErrors, fmt.Errorf(fmt.Sprintf(errPullRequestScan, int(currentPr.ID), repo.RepoName, e.Error())))
		}
		if shouldScan {
			spr := &ScanPullRequestCmd{dryRun: cmd.dryRun, dryRunRepoPath: path.Join(cmd.dryRunRepoPath, repo.RepoName), pullRequestDetails: &currentPr, gitManager: gm}
			if err = spr.Run(utils.RepoAggregator{repo}, client); err != nil {
				aggregatedErrors = errors.Join(aggregatedErrors, fmt.Errorf(fmt.Sprintf(errPullRequestScan, int(currentPr.ID), repo.RepoName, e.Error())))
			}
		} else {
			log.Debug(fmt.Sprintf("skipping scan for pull request number: %d", currentPr.ID))
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
