package scanpullrequest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
)

const (
	untrustedScanAllPrsWarning = "WARNING: 'scan-all-pull-requests' is no longer a supported flow, and it risks running build logic from untrusted sources. " +
		"Consider migrating to the 'scan-pull-request' command, or to Frogbot v3."
	untrustedScanAllPrsAllowedWarning = "WARNING: " + utils.AllowUntrustedScanAllPrsEnv + " is set, so pull requests from forks and from unverified sources are scanned. " +
		"Code from these pull requests runs on this machine with access to its credentials."
	untrustedScanAllPrsRestrictedWarning = "Only pull requests from the same repository are scanned. To scan other pull requests set " + utils.AllowUntrustedScanAllPrsEnv + "=true (not recommended)."
)

var errPullRequestScan = "pull request #%d scan in the '%s' repository returned the following error:\n%s"

type ScanAllPullRequestsCmd struct {
}

func (cmd ScanAllPullRequestsCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient, frogbotRepoConnection *utils.UrlAccessChecker) error {
	allowUntrusted, err := isUntrustedScanAllPrsAllowed()
	if err != nil {
		return err
	}
	log.Warn(untrustedScanAllPrsWarning)
	if allowUntrusted {
		log.Warn(untrustedScanAllPrsAllowedWarning)
	} else {
		log.Warn(untrustedScanAllPrsRestrictedWarning)
	}
	for _, config := range configAggregator {
		if config.GitProvider == vcsutils.GitHub {
			if err = verifyGitHubFrogbotEnvironment(client, &config); err != nil {
				return err
			}
		}
		log.Info("Scanning all open pull requests for repository:", config.RepoName)
		log.Info("-----------------------------------------------------------")
		config.OutputWriter.SetHasInternetConnection(frogbotRepoConnection.IsConnected())
		if err = scanAllPullRequests(config, client, allowUntrusted); err != nil {
			return err
		}
	}
	return nil
}

func isUntrustedScanAllPrsAllowed() (bool, error) {
	envValue := strings.TrimSpace(os.Getenv(utils.AllowUntrustedScanAllPrsEnv))
	if envValue == "" {
		return false, nil
	}
	allowed, err := strconv.ParseBool(envValue)
	if err != nil {
		return false, fmt.Errorf("the value of the %s environment is expected to be either TRUE or FALSE. The value received however is %s", utils.AllowUntrustedScanAllPrsEnv, envValue)
	}
	return allowed, nil
}

// A pull request is trusted only if its source is verifiably the same repository as its target.
// Missing source details are treated as untrusted.
func isPullRequestFromSameRepository(pr vcsclient.PullRequestInfo) bool {
	return pr.Source.Owner != "" && pr.Source.Repository != "" &&
		strings.EqualFold(pr.Source.Owner, pr.Target.Owner) &&
		strings.EqualFold(pr.Source.Repository, pr.Target.Repository)
}

// Scan pull requests as follows:
// a. Retrieve all open pull requests
// b. Skip pull requests that do not originate from the same repository, unless allowUntrusted is set
// c. Find the ones that should be scanned (new PRs or PRs with a 're-scan' comment)
// d. Audit the dependencies of the source and the target branches.
// e. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
func scanAllPullRequests(repo utils.Repository, client vcsclient.VcsClient, allowUntrusted bool) (err error) {
	openPullRequests, err := client.ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName)
	if err != nil {
		return err
	}
	for _, pr := range openPullRequests {
		if !allowUntrusted && !isPullRequestFromSameRepository(pr) {
			log.Warn(fmt.Sprintf("Skipping pull request %d since it does not originate from the repository itself (e.g. a fork). To scan it anyway set %s=true (not recommended).", pr.ID, utils.AllowUntrustedScanAllPrsEnv))
			continue
		}
		shouldScan, e := shouldScanPullRequest(repo, client, int(pr.ID))
		if e != nil {
			err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
		}
		if !shouldScan {
			log.Info("Pull Request", pr.ID, "has already been scanned before. If you wish to scan it again, please comment \"rescan\".")
			continue
		}
		repo.PullRequestDetails = pr
		if e = scanPullRequest(&repo, client); e != nil {
			// If error, write it in errList and continue to the next PR.
			err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
		}
	}
	return
}

func shouldScanPullRequest(repo utils.Repository, client vcsclient.VcsClient, prID int) (shouldScan bool, err error) {
	pullRequestsComments, err := utils.GetSortedPullRequestComments(client, repo.RepoOwner, repo.RepoName, prID)
	if err != nil {
		return
	}

	for _, comment := range pullRequestsComments {
		// If this a 're-scan' request comment
		if utils.IsFrogbotRescanComment(comment.Content) {
			return true, nil
		}
		// if this is a Frogbot 'scan results' comment and not 're-scan' request comment, do not scan this pull request.
		if outputwriter.IsFrogbotComment(comment.Content) {
			return false, nil
		}
	}
	// This is a new pull request, and it therefore should be scanned.
	return true, nil
}
