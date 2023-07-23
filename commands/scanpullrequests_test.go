package commands

import (
	"context"
	"fmt"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jfrog/frogbot/commands/testdata"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
)

var gitParams = &utils.Repository{
	OutputWriter: &utils.SimplifiedOutput{},
	Params: utils.Params{
		Git: utils.Git{
			ClientInfo: utils.ClientInfo{
				RepoOwner: "repo-owner",
				Branches:  []string{"master"},
				RepoName:  "repo-name",
			},
		},
	},
}

type MockParams struct {
	repoName         string
	repoOwner        string
	sourceBranchName string
	targetBranchName string
}

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=testdata/vcsclientmock.go -package=testdata github.com/jfrog/froggit-go/vcsclient VcsClient
func TestShouldScanPullRequestNewPR(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{}, nil)
	// Run handleFrogbotLabel
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesPrBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.True(t, shouldScan)
}

func TestShouldNotScanPullRequestReScan(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.VulnerabilitiesPrBannerSource) + "text \n table\n text text text", Created: time.Unix(1, 0)},
		{Content: utils.RescanRequestComment, Created: time.Unix(1, 1)},
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func TestShouldNotScanPullRequest(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{
		{Content: utils.GetSimplifiedTitle(utils.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
	}, nil)
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.NoError(t, err)
	assert.False(t, shouldScan)
}

func mockVcsClient(t *testing.T) *testdata.MockVcsClient {
	mockCtrl := gomock.NewController(t)
	return testdata.NewMockVcsClient(mockCtrl)
}

func TestShouldNotScanPullRequestError(t *testing.T) {
	// Init mock
	client := mockVcsClient(t)
	prID := 0
	client.EXPECT().ListPullRequestComments(context.Background(), gitParams.RepoOwner, gitParams.RepoName, prID).Return([]vcsclient.CommentInfo{}, fmt.Errorf("Bad Request"))
	shouldScan, err := shouldScanPullRequest(*gitParams, client, prID)
	assert.Error(t, err)
	assert.False(t, shouldScan)
}

func TestScanAllPullRequestsMultiRepo(t *testing.T) {
	server, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	failOnSecurityIssues := false
	firstRepoParams := utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues: &failOnSecurityIssues,
			Projects: []utils.Project{{
				InstallCommandName: "npm",
				InstallCommandArgs: []string{"i"},
				WorkingDirs:        []string{utils.RootDir},
				UseWrapper:         &utils.TrueVal,
			}},
		},
		Git: gitParams.Git,
	}
	secondRepoParams := utils.Params{
		Git: gitParams.Git,
		Scan: utils.Scan{
			FailOnSecurityIssues: &failOnSecurityIssues,
			Projects:             []utils.Project{{WorkingDirs: []string{utils.RootDir}, UseWrapper: &utils.TrueVal}}},
	}

	configAggregator := utils.RepoAggregator{
		{
			OutputWriter: &utils.SimplifiedOutput{},
			Server:       server,
			Params:       firstRepoParams,
		},
		{
			OutputWriter: &utils.SimplifiedOutput{},
			Server:       server,
			Params:       secondRepoParams,
		},
	}
	mockParams := []MockParams{
		{gitParams.RepoName, gitParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"},
		{gitParams.RepoName, gitParams.RepoOwner, "test-proj-pip-with-vulnerability", "test-proj-pip"},
	}
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, mockParams...)
	scanAllPullRequestsCmd := ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(configAggregator, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 4)
	expectedMessage := "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical | Not Applicable |minimist:1.2.5 | minimist:1.2.5 | [0.2.4]<br><br>[1.2.6] |\n\n</div>\n\n## 👇 Details\n\n\n\n\n- **Severity** 💀 Critical\n- **Contextual Analysis:** Not Applicable\n- **Package Name:** minimist\n- **Current Version:** 1.2.5\n- **Fixed Versions:** [0.2.4],[1.2.6]\n- **CVE:** CVE-2021-44906\n\n**Description:**\n\n[Minimist](https://github.com/substack/minimist) is a simple and very popular argument parser. It is used by more than 14 million by Mar 2022. This package developers stopped developing it since April 2020 and its community released a [newer version](https://github.com/meszaros-lajos-gyorgy/minimist-lite) supported by the community.\n\n\nAn incomplete fix for [CVE-2020-7598](https://nvd.nist.gov/vuln/detail/CVE-2020-7598) partially blocked prototype pollution attacks. Researchers discovered that it does not check for constructor functions which means they can be overridden. This behavior can be triggered easily when using it insecurely (which is the common usage). For example:\n```\nvar argv = parse(['--_.concat.constructor.prototype.y', '123']);\nt.equal((function(){}).foo, undefined);\nt.equal(argv.y, undefined);\n```\nIn this example, `prototype.y`  is assigned with `123` which will be derived to every newly created object. \n\nThis vulnerability can be triggered when the attacker-controlled input is parsed using Minimist without any validation. As always with prototype pollution, the impact depends on the code that follows the attack, but denial of service is almost always guaranteed.\n\n**Remediation:**\n\n##### Development mitigations\n\nAdd the `Object.freeze(Object.prototype);` directive once at the beginning of your main JS source code file (ex. `index.js`), preferably after all your `require` directives. This will prevent any changes to the prototype object, thus completely negating prototype pollution attacks.\n\n\n\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, frogbotMessages[0])
	expectedMessage = "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, frogbotMessages[1])
	expectedMessage = "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n## 📦 Vulnerable Dependencies \n\n### ✍️ Summary\n\n<div align=\"center\">\n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | Undetermined |pip-example:1.2.3 | pyjwt:1.7.1 | [2.4.0] |\n\n</div>\n\n## 👇 Details\n\n\n\n\n- **Severity** 🔥 High\n- **Contextual Analysis:** Undetermined\n- **Package Name:** pyjwt\n- **Current Version:** 1.7.1\n- **Fixed Version:** [2.4.0]\n- **CVE:** CVE-2022-29217\n\n**Description:**\n\n[PyJWT](https://pypi.org/project/PyJWT) is a Python implementation of the RFC 7519 standard (JSON Web Tokens). [JSON Web Tokens](https://jwt.io/) are an open, industry standard method for representing claims securely between two parties. A JWT comes with an inline signature that is meant to be verified by the receiving application. JWT supports multiple standard algorithms, and the algorithm itself is **specified in the JWT token itself**.\n\nThe PyJWT library uses the signature-verification algorithm that is specified in the JWT token (that is completely attacker-controlled), however - it requires the validating application to pass an `algorithms` kwarg that specifies the expected algorithms in order to avoid key confusion. Unfortunately -  a non-default value `algorithms=jwt.algorithms.get_default_algorithms()` exists that allows all algorithms.\nThe PyJWT library also tries to mitigate key confusions in this case, by making sure that public keys are not used as an HMAC secret. For example, HMAC secrets that begin with `-----BEGIN PUBLIC KEY-----` are rejected when encoding a JWT.\n\nIt has been discovered that due to missing key-type checks, in cases where -\n1. The vulnerable application expects to receive a JWT signed with an Elliptic-Curve key (one of the algorithms `ES256`, `ES384`, `ES512`, `EdDSA`)\n2. The vulnerable application decodes the JWT token using the non-default kwarg `algorithms=jwt.algorithms.get_default_algorithms()` (or alternatively, `algorithms` contain both an HMAC-based algorithm and an EC-based algorithm)\n\nAn attacker can create an HMAC-signed (ex. `HS256`) JWT token, using the (well-known!) EC public key as the HMAC key. The validating application will accept this JWT token as a valid token.\n\nFor example, an application might have planned to validate an `EdDSA`-signed token that was generated as follows -\n```python\n# Making a good jwt token that should work by signing it with the private key\nencoded_good = jwt.encode({\"test\": 1234}, priv_key_bytes, algorithm=\"EdDSA\")\n```\nAn attacker in posession of the public key can generate an `HMAC`-signed token to confuse PyJWT - \n```python\n# Using HMAC with the public key to trick the receiver to think that the public key is a HMAC secret\nencoded_bad = jwt.encode({\"test\": 1234}, pub_key_bytes, algorithm=\"HS256\")\n```\n\nThe following vulnerable `decode` call will accept BOTH of the above tokens as valid - \n```\ndecoded = jwt.decode(encoded_good, pub_key_bytes, \nalgorithms=jwt.algorithms.get_default_algorithms())\n```\n\n**Remediation:**\n\n##### Development mitigations\n\nUse a specific algorithm instead of `jwt.algorithms.get_default_algorithms`.\nFor example, replace the following call - \n`jwt.decode(encoded_jwt, pub_key_bytes, algorithms=jwt.algorithms.get_default_algorithms())`\nWith -\n`jwt.decode(encoded_jwt, pub_key_bytes, algorithms=[\"ES256\"])`\n\n\n\n\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, frogbotMessages[2])
	expectedMessage = "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/noVulnerabilityBannerPR.png)](https://github.com/jfrog/frogbot#readme)\n<div align=\"center\">\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)\n\n</div>\n"
	assert.Equal(t, expectedMessage, frogbotMessages[3])
}

func TestScanAllPullRequests(t *testing.T) {
	// This integration test, requires JFrog platform connection details
	server, restoreEnv := verifyEnv(t)
	defer restoreEnv()
	falseVal := false
	gitParams.Git.GitProvider = vcsutils.BitbucketServer
	params := utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues: &falseVal,
			Projects: []utils.Project{{
				InstallCommandName: "npm",
				InstallCommandArgs: []string{"i"},
				WorkingDirs:        []string{"."},
				UseWrapper:         &utils.TrueVal,
			}},
		},
		Git: gitParams.Git,
	}
	repoParams := &utils.Repository{
		OutputWriter: &utils.SimplifiedOutput{},
		Server:       server,
		Params:       params,
	}
	paramsAggregator := utils.RepoAggregator{}
	paramsAggregator = append(paramsAggregator, *repoParams)
	var frogbotMessages []string
	client := getMockClient(t, &frogbotMessages, MockParams{repoParams.RepoName, repoParams.RepoOwner, "test-proj-with-vulnerability", "test-proj"})
	scanAllPullRequestsCmd := ScanAllPullRequestsCmd{}
	err := scanAllPullRequestsCmd.Run(paramsAggregator, client)
	assert.NoError(t, err)
	assert.Len(t, frogbotMessages, 2)
	expectedMessage := "**🚨 Frogbot scanned this pull request and found the below:**\n\n---\n## 📦 Vulnerable Dependencies\n---\n\n### ✍️ Summary \n\n| SEVERITY                | CONTEXTUAL ANALYSIS                  | DIRECT DEPENDENCIES                  | IMPACTED DEPENDENCY                   | FIXED VERSIONS                       |\n| :---------------------: | :----------------------------------: | :----------------------------------: | :-----------------------------------: | :---------------------------------: | \n| Critical | Not Applicable | minimist:1.2.5 | minimist:1.2.5 | [0.2.4], [1.2.6] |\n\n---\n### 👇 Details\n---\n\n\n#### minimist 1.2.5\n\n\n- **Severity** 💀 Critical\n- **Contextual Analysis:** Not Applicable\n- **Package Name:** minimist\n- **Current Version:** 1.2.5\n- **Fixed Versions:** [0.2.4],[1.2.6]\n- **CVE:** CVE-2021-44906\n\n**Description:**\n\n[Minimist](https://github.com/substack/minimist) is a simple and very popular argument parser. It is used by more than 14 million by Mar 2022. This package developers stopped developing it since April 2020 and its community released a [newer version](https://github.com/meszaros-lajos-gyorgy/minimist-lite) supported by the community.\n\n\nAn incomplete fix for [CVE-2020-7598](https://nvd.nist.gov/vuln/detail/CVE-2020-7598) partially blocked prototype pollution attacks. Researchers discovered that it does not check for constructor functions which means they can be overridden. This behavior can be triggered easily when using it insecurely (which is the common usage). For example:\n```\nvar argv = parse(['--_.concat.constructor.prototype.y', '123']);\nt.equal((function(){}).foo, undefined);\nt.equal(argv.y, undefined);\n```\nIn this example, `prototype.y`  is assigned with `123` which will be derived to every newly created object. \n\nThis vulnerability can be triggered when the attacker-controlled input is parsed using Minimist without any validation. As always with prototype pollution, the impact depends on the code that follows the attack, but denial of service is almost always guaranteed.\n\n**Remediation:**\n\n##### Development mitigations\n\nAdd the `Object.freeze(Object.prototype);` directive once at the beginning of your main JS source code file (ex. `index.js`), preferably after all your `require` directives. This will prevent any changes to the prototype object, thus completely negating prototype pollution attacks.\n\n\n\n\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)"
	assert.Equal(t, expectedMessage, frogbotMessages[0])
	expectedMessage = "**👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies.** \n\n\n[JFrog Frogbot](https://github.com/jfrog/frogbot#readme)"
	assert.Equal(t, expectedMessage, frogbotMessages[1])
}

func getMockClient(t *testing.T, frogbotMessages *[]string, mockParams ...MockParams) *testdata.MockVcsClient {
	// Init mock
	client := mockVcsClient(t)
	for _, params := range mockParams {
		sourceBranchInfo := vcsclient.BranchInfo{Name: params.sourceBranchName, Repository: params.repoName}
		targetBranchInfo := vcsclient.BranchInfo{Name: params.targetBranchName, Repository: params.repoName}
		// Return 2 pull requests to scan, the first with issues the second "clean".
		client.EXPECT().ListOpenPullRequests(context.Background(), params.repoOwner, params.repoName).Return([]vcsclient.PullRequestInfo{{ID: 0, Source: sourceBranchInfo, Target: targetBranchInfo}, {ID: 1, Source: targetBranchInfo, Target: targetBranchInfo}}, nil)
		// Return empty comments slice so expect the code to scan both pull requests.
		client.EXPECT().ListPullRequestComments(context.Background(), params.repoOwner, params.repoName, gomock.Any()).Return([]vcsclient.CommentInfo{}, nil).AnyTimes()
		// Copy test project according to the given branch name, instead of download it.
		client.EXPECT().DownloadRepository(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(fakeRepoDownload).AnyTimes()
		// Capture the result comment post
		client.EXPECT().AddPullRequestComment(context.Background(), params.repoOwner, params.repoName, gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _, _, content string, _ int) error {
			*frogbotMessages = append(*frogbotMessages, content)
			return nil
		}).AnyTimes()
	}
	return client
}

// To accurately simulate the "real" repository download, the tests project must be located in the same directory.
// The process involves the following steps:
// 1. First, the "test-proj-with-vulnerability" project, which includes a "test-proj" directory, will be copied to a temporary directory with a random name. This project will be utilized during the source auditing phase to mimic a pull request with a new vulnerable dependency.
// 2. Next, a second "download" will take place within the first temporary directory. As a result, the "test-proj" directory will be discovered and copied to a second temporary directory with another random name. This copied version will be used during the target auditing phase.
func fakeRepoDownload(_ context.Context, _, _, testProject, targetDir string) error {
	err := fileutils.CopyDir(testProject, targetDir, true, []string{})
	if err != nil {
		return err
	}
	sourceDir, err := filepath.Abs(filepath.Join("testdata", "scanpullrequests", testProject))
	if err != nil {
		return err
	}
	return fileutils.CopyDir(sourceDir, targetDir, true, []string{})
}
