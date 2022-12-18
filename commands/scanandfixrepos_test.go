package commands

import (
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanAndFixRepos(t *testing.T) {
	params, restoreEnv := verifyEnv(t)
	defer restoreEnv()

	server := httptest.NewServer(createHttpHandler(t))
	defer server.Close()

	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	var configAggregator utils.FrogbotConfigAggregator

}

func createHttpHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

	}
}
