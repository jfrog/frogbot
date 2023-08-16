package utils

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/artifactory/services"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/http/jfroghttpclient"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var timestamp = time.Now().Unix()

func initResolveDependencyTest(t *testing.T) {
	if !*TestResolveDependency {
		t.Skip("Skipping Resolve Dependency tests. To run Resolve Dependency tests add the '-test.Resolve-Dependency' option.")
	}
}

func setTestEnvironment(t *testing.T, project string, server *config.ServerDetails) (func(), string) {
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	sourceDir := filepath.Join("..", "testdata", "projects", project)
	assert.NoError(t, fileutils.CopyDir(sourceDir, tmpDir, true, nil))
	restoreDir, err := Chdir(tmpDir)
	assert.NoError(t, err)
	deleteRemoteRepoFunc, repoKey := createRemoteRepo(t, project, server)
	return func() {
		deleteRemoteRepoFunc()
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}, repoKey
}

func createNpmRemoteRepo(t *testing.T, remoteRepoService *services.RemoteRepositoryService) string {
	repoParams := services.NewNpmRemoteRepositoryParams()
	timestamp++
	repoParams.Key = fmt.Sprintf("frogbot-npm-remote-repo-%d-%s", timestamp, runtime.GOOS)
	repoParams.Url = "https://registry.npmjs.org"
	assert.NoError(t, remoteRepoService.Npm(repoParams))
	return repoParams.Key
}

func createNugetRemoteRepo(t *testing.T, remoteRepoService *services.RemoteRepositoryService) string {
	repoParams := services.NewNugetRemoteRepositoryParams()
	timestamp++
	repoParams.Key = fmt.Sprintf("frogbot-nuget-remote-repo-%d-%s", timestamp, runtime.GOOS)
	repoParams.Url = "https://www.nuget.org/"
	repoParams.FeedContextPath = "api/v1"
	repoParams.DownloadContextPath = "api/v1/package"
	repoParams.V3FeedUrl = "https://api.nuget.org/v3/index.json"
	repoParams.ForceNugetAuthentication = &TrueVal
	assert.NoError(t, remoteRepoService.Nuget(repoParams))
	return repoParams.Key
}

func createRemoteRepo(t *testing.T, project string, server *config.ServerDetails) (func(), string) {
	rtDetails, err := server.CreateArtAuthConfig()
	assert.NoError(t, err)
	jfrogClient, err := createJfrogHttpClient(&rtDetails)
	assert.NoError(t, err)
	createRemoteRepoServices := services.NewRemoteRepositoryService(jfrogClient, false)
	createRemoteRepoServices.ArtDetails = rtDetails
	var repoKey string
	switch project {
	case "npm", "yarn2", "yarn1":
		repoKey = createNpmRemoteRepo(t, createRemoteRepoServices)
	case "dotnet":
		repoKey = createNugetRemoteRepo(t, createRemoteRepoServices)
	}

	deleteRemoteRepoServices := services.NewDeleteRepositoryService(jfrogClient)
	deleteRemoteRepoServices.ArtDetails = rtDetails
	return func() {
		assert.NoError(t, deleteRemoteRepoServices.Delete(repoKey))
	}, repoKey
}

func createJfrogHttpClient(artDetails *auth.ServiceDetails) (*jfroghttpclient.JfrogHttpClient, error) {
	return jfroghttpclient.JfrogClientBuilder().
		SetClientCertPath((*artDetails).GetClientCertPath()).
		SetClientCertKeyPath((*artDetails).GetClientCertKeyPath()).
		Build()
}

func TestResolveDependencies(t *testing.T) {
	initResolveDependencyTest(t)
	params, restoreEnv := VerifyEnv(t)
	defer restoreEnv()
	testCases := []struct {
		name              string
		tech              string
		scanSetup         *ScanDetails
		repoKey           string
		resolveFunc       func(scanSetup *ScanDetails) ([]byte, error)
		shouldExpectError bool
	}{
		{
			name: "Resolve NPM dependencies",
			tech: "npm",
			scanSetup: &ScanDetails{
				ServerDetails: &params,
				Project: &Project{
					InstallCommandName: "npm",
					InstallCommandArgs: []string{"install"},
				}},
			resolveFunc:       resolveNpmDependencies,
			shouldExpectError: false,
		},
		{
			name: "Resolve Yarn V2 dependencies",
			tech: "yarn2",
			scanSetup: &ScanDetails{
				ServerDetails: &params,
				Project: &Project{
					InstallCommandName: "yarn",
					InstallCommandArgs: []string{"install"},
				}},
			resolveFunc:       resolveYarnDependencies,
			shouldExpectError: false,
		},
		{
			name: "Resolve Yarn V1 dependencies",
			tech: "yarn1",
			scanSetup: &ScanDetails{
				ServerDetails: &params,
				Project: &Project{
					InstallCommandName: "yarn",
					InstallCommandArgs: []string{"install"},
				}},
			resolveFunc:       resolveYarnDependencies,
			shouldExpectError: true,
		},
		{
			name: "Resolve .NET dependencies",
			tech: "dotnet",
			scanSetup: &ScanDetails{
				ServerDetails: &params,
				Project: &Project{
					DepsRepo:           "frogbot-nuget-remote-tests",
					InstallCommandName: "dotnet",
					InstallCommandArgs: []string{"restore"},
				}},
			resolveFunc:       resolveDotnetDependencies,
			shouldExpectError: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			restoreFunc, repoKey := setTestEnvironment(t, test.tech, &params)
			defer restoreFunc()
			test.scanSetup.Project.DepsRepo = repoKey
			output, err := test.resolveFunc(test.scanSetup)
			if test.shouldExpectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err, "command's output:/n"+string(output))
			}
		})
	}
}
