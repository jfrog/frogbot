package utils

import (
	"net/textproto"
	"testing"

	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jordan-wright/email"
	"github.com/stretchr/testify/assert"
)

func TestGetSecretsEmailContent(t *testing.T) {
	secrets := []formats.SourceCodeRow{
		{
			SeverityDetails: formats.SeverityDetails{Severity: "High"},
			Location: formats.Location{
				File: "/config.yaml", StartLine: 12, StartColumn: 30, Snippet: "pass*****"},
		},
		{
			SeverityDetails: formats.SeverityDetails{Severity: "Medium"},
			Location: formats.Location{
				File: "/server-conf.json", StartLine: 15, StartColumn: 20, Snippet: "pass*****"}},
	}
	// Test for results including the "Pull Request" keyword
	expected := "\n<!DOCTYPE html>\n<html>\n<head>\n    <title>Frogbot Secret Detection</title>\n    <style>\n        body {\n            font-family: Arial, sans-serif;\n            background-color: #f5f5f5;\n        }\n        table {\n            border-collapse: collapse;\n            width: 80%;\n        }\n        th, td {\n            padding: 10px;\n            border: 1px solid #ccc;\n        }\n        th {\n            background-color: #f2f2f2;\n        }\n        tr:nth-child(even) {\n            background-color: #f9f9f9;\n        }\n        tr:hover {\n            background-color: #f5f5f5;\n        }\n        .table-container {\n            max-width: 700px;\n            padding: 20px;\n            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);\n            border-radius: 10px;\n            overflow: hidden;\n            background-color: #fff;\n\t\t\tmargin-top: 10px;\n        }\n        .ignore-comments {\n            margin-top: 10px;\n\t\t\tmargin-bottom: 5px;\n            border-radius: 5px;\n        }\n    </style>\n</head>\n<body>\n\t<div>\n\t\tThe following potential exposed secrets in your <a href=\"https://github.com/owner/repo/pullrequest/1\">pull request</a> have been detected by <a href=\"https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot\">Frogbot</a>\n\t\t<br/>\n\t\t<table class=\"table-container\">\n            <thead>\n                <tr>\n                    <th>FILE</th>\n                    <th>LINE:COLUMN</th>\n                    <th>SECRET</th>\n                </tr>\n            </thead>\n            <tbody>\n                \n\t\t\t\t<tr>\n\t\t\t\t\t<td> /config.yaml </td>\n\t\t\t\t\t<td> 12:30 </td>\n\t\t\t\t\t<td> pass***** </td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td> /server-conf.json </td>\n\t\t\t\t\t<td> 15:20 </td>\n\t\t\t\t\t<td> pass***** </td>\n\t\t\t\t</tr>\n            </tbody>\n        </table>\n\t\t<div class=\"ignore-comments\">\n\t\t<b>NOTE:</b> If you'd like Frogbot to ignore the lines with the potential secrets, add a comment that includes the <b>jfrog-ignore</b> keyword above the lines with the secrets.\t\n\t\t</div>\n\t</div>\n</body>\n</html>"
	actualContent := getSecretsEmailContent(secrets, vcsutils.GitHub, "https://github.com/owner/repo/pullrequest/1")
	assert.Equal(t, expected, actualContent)

	// Test for results including the "Merge Request" keyword
	expected = "\n<!DOCTYPE html>\n<html>\n<head>\n    <title>Frogbot Secret Detection</title>\n    <style>\n        body {\n            font-family: Arial, sans-serif;\n            background-color: #f5f5f5;\n        }\n        table {\n            border-collapse: collapse;\n            width: 80%;\n        }\n        th, td {\n            padding: 10px;\n            border: 1px solid #ccc;\n        }\n        th {\n            background-color: #f2f2f2;\n        }\n        tr:nth-child(even) {\n            background-color: #f9f9f9;\n        }\n        tr:hover {\n            background-color: #f5f5f5;\n        }\n        .table-container {\n            max-width: 700px;\n            padding: 20px;\n            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);\n            border-radius: 10px;\n            overflow: hidden;\n            background-color: #fff;\n\t\t\tmargin-top: 10px;\n        }\n        .ignore-comments {\n            margin-top: 10px;\n\t\t\tmargin-bottom: 5px;\n            border-radius: 5px;\n        }\n    </style>\n</head>\n<body>\n\t<div>\n\t\tThe following potential exposed secrets in your <a href=\"https://github.com/owner/repo/pullrequest/1\">merge request</a> have been detected by <a href=\"https://jfrog.com/help/r/jfrog-security-user-guide/developers/frogbot\">Frogbot</a>\n\t\t<br/>\n\t\t<table class=\"table-container\">\n            <thead>\n                <tr>\n                    <th>FILE</th>\n                    <th>LINE:COLUMN</th>\n                    <th>SECRET</th>\n                </tr>\n            </thead>\n            <tbody>\n                \n\t\t\t\t<tr>\n\t\t\t\t\t<td> /config.yaml </td>\n\t\t\t\t\t<td> 12:30 </td>\n\t\t\t\t\t<td> pass***** </td>\n\t\t\t\t</tr>\n\t\t\t\t<tr>\n\t\t\t\t\t<td> /server-conf.json </td>\n\t\t\t\t\t<td> 15:20 </td>\n\t\t\t\t\t<td> pass***** </td>\n\t\t\t\t</tr>\n            </tbody>\n        </table>\n\t\t<div class=\"ignore-comments\">\n\t\t<b>NOTE:</b> If you'd like Frogbot to ignore the lines with the potential secrets, add a comment that includes the <b>jfrog-ignore</b> keyword above the lines with the secrets.\t\n\t\t</div>\n\t</div>\n</body>\n</html>"
	actualContent = getSecretsEmailContent(secrets, vcsutils.GitLab, "https://github.com/owner/repo/pullrequest/1")
	assert.Equal(t, expected, actualContent)
}

func TestPrepareEmail(t *testing.T) {
	sender := "JFrog Frogbot <frogbot@jfrog.com>"
	subject := outputwriter.FrogbotTitlePrefix + " Potential secrets detected"
	content := "content"
	emailDetails := EmailDetails{EmailReceivers: []string{"receiver@jfrog.com"}}
	expectedEmailObject := &email.Email{
		From:    sender,
		To:      emailDetails.EmailReceivers,
		Subject: subject,
		HTML:    []byte(content),
		Headers: textproto.MIMEHeader{},
	}
	actualEmailObject := prepareEmail(sender, subject, content, emailDetails)
	assert.Equal(t, expectedEmailObject, actualEmailObject)
}

func TestGetEmailReceiversFromCommits(t *testing.T) {
	commits := []vcsclient.CommitInfo{
		{AuthorEmail: "test1@jfrog.com"},
		{AuthorEmail: "test2@jfrog.com"},
		{AuthorEmail: "receiver1@jfrog.com"},
		{AuthorEmail: "test3@jfrog.no.reply.com"},
		{AuthorEmail: "test3@jfrog.noreply.com"},
		{AuthorEmail: "test3@jfrog.no-reply.com"},
		{AuthorEmail: "test3@jfrog.frogbot.com"},
		{AuthorEmail: ""},
	}
	preConfiguredEmailReceivers := []string{"receiver1@jfrog.com", "receiver2@jfrog.com"}
	finalEmailReceiversList, err := getEmailReceiversFromCommits(commits, preConfiguredEmailReceivers)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"test1@jfrog.com", "test2@jfrog.com"}, finalEmailReceiversList)
}
