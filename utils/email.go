package utils

import (
	"context"
	"fmt"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jordan-wright/email"
	"net/smtp"
	"strings"
)

var blacklistedEmailAddresses = []string{"no-reply", "no_reply", "noreply", "no.reply", "frogbot"}

type SecretsEmailDetails struct {
	gitClient       vcsclient.VcsClient
	gitProvider     vcsutils.VcsProvider
	branch          string
	repoName        string
	repoOwner       string
	detectedSecrets []formats.SourceCodeRow
	pullRequestLink string
	EmailDetails
}

func NewSecretsEmailDetails(gitClient vcsclient.VcsClient, repoConfig *Repository, secrets []formats.SourceCodeRow) *SecretsEmailDetails {
	secretsEmailDetails := &SecretsEmailDetails{
		gitClient:       gitClient,
		EmailDetails:    repoConfig.EmailDetails,
		gitProvider:     repoConfig.GitProvider,
		repoOwner:       repoConfig.PullRequestDetails.Source.Owner,
		repoName:        repoConfig.PullRequestDetails.Source.Repository,
		branch:          repoConfig.PullRequestDetails.Source.Name,
		detectedSecrets: secrets,
		pullRequestLink: repoConfig.PullRequestDetails.URL,
	}
	return secretsEmailDetails
}

func AlertSecretsExposed(secretsDetails *SecretsEmailDetails) (err error) {
	if len(secretsDetails.detectedSecrets) == 0 {
		return
	}
	var relevantEmailReceivers []string
	if relevantEmailReceivers, err = getRelevantEmailReceivers(secretsDetails.gitClient, secretsDetails.repoOwner, secretsDetails.repoName, secretsDetails.branch, secretsDetails.EmailReceivers); err != nil {
		return
	}
	secretsDetails.EmailReceivers = append(secretsDetails.EmailReceivers, relevantEmailReceivers...)
	emailDetails := secretsDetails.EmailDetails
	emailContent := getSecretsEmailContent(secretsDetails.detectedSecrets, secretsDetails.gitProvider, secretsDetails.pullRequestLink)
	sender := fmt.Sprintf("JFrog Frogbot <%s>", emailDetails.SmtpUser)
	subject := outputwriter.FrogbotTitlePrefix + " Potential secrets detected"
	return sendEmail(sender, subject, emailContent, emailDetails)
}

func getSecretsEmailContent(secrets []formats.SourceCodeRow, gitProvider vcsutils.VcsProvider, pullRequestLink string) string {
	var tableContent strings.Builder
	for _, secret := range secrets {
		tableContent.WriteString(
			fmt.Sprintf(outputwriter.SecretsEmailTableRow,
				secret.File,
				secret.StartLine,
				secret.StartColumn,
				secret.Snippet))
	}
	pullOrMergeRequest := "pull request"
	if gitProvider == vcsutils.GitLab {
		pullOrMergeRequest = "merge request"
	}

	return fmt.Sprintf(
		outputwriter.SecretsEmailHTMLTemplate,
		outputwriter.SecretsEmailCSS,
		pullRequestLink,
		pullOrMergeRequest,
		tableContent.String(),
	)
}

func sendEmail(sender, subject, content string, emailDetails EmailDetails) error {
	e := prepareEmail(sender, subject, content, emailDetails)
	smtpAuth := smtp.PlainAuth("", emailDetails.SmtpUser, emailDetails.SmtpPassword, emailDetails.SmtpServer)
	return e.Send(strings.Join([]string{emailDetails.SmtpServer, emailDetails.SmtpPort}, ":"), smtpAuth)
}

func prepareEmail(sender, subject, content string, emailDetails EmailDetails) *email.Email {
	e := email.NewEmail()
	e.From = sender
	e.To = emailDetails.EmailReceivers
	e.Subject = subject
	e.HTML = []byte(content)
	return e
}

func getRelevantEmailReceivers(client vcsclient.VcsClient, repoOwner, repoName, branch string, emailReceivers []string) ([]string, error) {
	commits, err := client.GetCommits(context.Background(), repoOwner, repoName, branch)
	if err != nil {
		return nil, err
	}

	return getEmailReceiversFromCommits(commits, emailReceivers)
}

func getEmailReceiversFromCommits(commits []vcsclient.CommitInfo, preConfiguredEmailReceivers []string) ([]string, error) {
	emailReceivers := []string{}
	for _, commit := range commits {
		if shouldExcludeEmailAddress(commit.AuthorEmail, preConfiguredEmailReceivers) {
			continue
		}
		emailReceivers = append(emailReceivers, commit.AuthorEmail)
	}

	return emailReceivers, nil
}

func shouldExcludeEmailAddress(emailAddress string, preConfiguredEmailReceivers []string) bool {
	if emailAddress == "" {
		return true
	}
	for _, blackListedEmail := range blacklistedEmailAddresses {
		if strings.Contains(emailAddress, blackListedEmail) {
			return true
		}
	}
	for _, preConfiguredEmailAddress := range preConfiguredEmailReceivers {
		if emailAddress == preConfiguredEmailAddress {
			return true
		}
	}
	return false
}
