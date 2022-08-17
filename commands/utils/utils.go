package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/artifactory/usage"
	clientLog "github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
)

type ErrMissingEnv struct {
	VariableName string
}

func (m *ErrMissingEnv) Error() string {
	return fmt.Sprintf("'%s' environment variable is missing", m.VariableName)
}

func Chdir(dir string) (cbk func() error, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err = os.Chdir(dir); err != nil {
		return nil, err
	}
	return func() error { return os.Chdir(wd) }, err
}

func ReportUsage(commandName string, serverDetails *config.ServerDetails, usageReportSent chan<- error) {
	var err error
	defer func() {
		// The usage reporting is meant to run asynchronously, so that the actual action isn't delayed.
		// It is however important to the application to not exit before the reporting is finished. That is, in case the reporting takes longer than the action.
		usageReportSent <- err
	}()
	if serverDetails.ArtifactoryUrl == "" {
		return
	}
	clientLog.Debug(usage.ReportUsagePrefix + "Sending info...")
	serviceManager, err := utils.CreateServiceManager(serverDetails, -1, 0, false)
	if err != nil {
		clientLog.Debug(usage.ReportUsagePrefix + err.Error())
		return
	}
	err = usage.SendReportUsage(productId, commandName, serviceManager)
	if err != nil {
		clientLog.Debug(err.Error())
		return
	}
}

func Md5Hash(values ...string) (string, error) {
	hash := crypto.MD5.New()
	for _, ob := range values {
		_, err := fmt.Fprint(hash, ob)
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// UploadScanToGitProvider uploads scan results to the relevant git provider in order to view the scan in the Git provider code scanning UI
func UploadScanToGitProvider(scanResults []services.ScanResponse, params *FrogbotParams, client vcsclient.VcsClient) error {
	if params.GitProvider.String() != vcsutils.GitHub.String() {
		clientLog.Info("Upload Scan to " + params.GitProvider.String() + " is currently unsupported.")
		return nil
	}
	// Don't do anything if scanResults is empty
	if xrayutils.IsEmptyScanResponse(scanResults) {
		return nil
	}
	includeVulnerabilities := params.Project == "" && params.Watches == ""
	scan, err := xrayutils.GenerateSarifFileFromScan(scanResults, includeVulnerabilities, false)
	if err != nil {
		return err
	}
	_, err = client.UploadCodeScanning(context.Background(), params.RepoOwner, params.Repo, params.BaseBranch, scan)
	if err != nil {
		return errors.New("Upload Scan to " + params.GitProvider.String() + " is currently unsupported.")
	}

	return nil
}
