package outputwriter

//func TestGetAggregatedPullRequestTitle(t *testing.T) {
//	tests := []struct {
//		tech     coreutils.Technology
//		expected string
//	}{
//		{tech: "", expected: "[🐸 Frogbot] Update dependencies"},
//		{tech: coreutils.Maven, expected: "[🐸 Frogbot] Update Maven dependencies"},
//		{tech: coreutils.Gradle, expected: "[🐸 Frogbot] Update Gradle dependencies"},
//		{tech: coreutils.Npm, expected: "[🐸 Frogbot] Update npm dependencies"},
//		{tech: coreutils.Yarn, expected: "[🐸 Frogbot] Update Yarn dependencies"},
//	}
//
//	for _, test := range tests {
//		title := GetAggregatedPullRequestTitle(test.tech)
//		assert.Equal(t, test.expected, title)
//	}
//}
//
//func TestSendEmailIfSecretsExposed(t *testing.T) {
//	secrets := []utils.IacOrSecretResult{
//		{Severity: "High", File: "/config.yaml", LineColumn: "12:30", Text: "pass*****"},
//		{Severity: "Medium", File: "/server-conf.json", LineColumn: "15:20", Text: "pass*****"},
//	}
//	emailDetails := utils2.EmailDetails{
//		SmtpServer:     "smtp.server.com",
//		SmtpPort:       "12",
//		SmtpAuthUser:   "test",
//		SmtpAuthPass:   "testpass",
//		EmailReceivers: []string{"user1@company.com", "user2@company.com"},
//	}
//	logo := getFullResourceUrl(VulnerabilitiesMrBannerSource)
//	assert.NoError(t, sendEmailIfSecretsExposed(secrets, emailDetails, string(logo)))
//}
//
//func TestSendEmail(t *testing.T) {
//	assert.NoError(t, sendEmail("JFrog Frogbot <frogbot@service.jfrog.com>", "Frogbot detected Potential Secrets", `
//
//<!DOCTYPE html>
//<html>
//<head>
//    <title>Frogbot Secret Detection</title>
//    <style>
//        body {
//            text-align: center;
//            font-family: Arial, sans-serif;
//        }
//        a img {
//            display: block;
//            margin: 0 auto;
//            max-width: 100%;
//        }
//        table {
//            margin: 20px auto;
//            border-collapse: collapse;
//            width: 80%;
//        }
//        th, td {
//            padding: 10px;
//            border: 1px solid #ccc;
//            text-align: center;
//        }
//        th {
//            background-color: #f2f2f2;
//        }
//        tr:nth-child(even) {
//            background-color: #f9f9f9;
//        }
//        tr:hover {
//            background-color: #f5f5f5;
//        }
//        img.severity-icon {
//            max-height: 30px;
//            vertical-align: middle;
//        }
//        h1 {
//            font-size: 24px;
//            color: #333;
//            margin-bottom: 20px;
//        }
//        .table-container {
//            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
//            border-radius: 10px;
//            overflow: hidden;
//            background-color: #fff;
//        }
//    </style>
//</head>
//<body>
//    <div class="table-container">
//        <a href="https://github.com/jfrog/frogbot#readme">
//            <img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerMR.png" alt="Banner">
//        </a>
//        <table>
//            <thead>
//                <tr>
//                    <th>SEVERITY</th>
//                    <th>FILE</th>
//                    <th>LINE:COLUMN</th>
//                    <th>TEXT</th>
//                </tr>
//            </thead>
//            <tbody>
//
//				<tr>
//					<td><img class="severity-icon" src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png" alt="severity"> High</td>
//					<td>/config.yaml</td>
//					<td>12:30</td>
//					<td>pass*****/td>
//				</tr>
//				<tr>
//					<td><img class="severity-icon" src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png" alt="severity"> Medium</td>
//					<td>/server-conf.json</td>
//					<td>15:20</td>
//					<td>pass*****/td>
//				</tr>
//            </tbody>
//        </table>
//    </div>
//</body>
//</html>`, utils2.EmailDetails{EmailReceivers: []string{"omerz@jfrog.com"}}))
//}
