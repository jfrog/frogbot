package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyLocalFileMatchesRemote(t *testing.T) {
	content := []byte("frogbot-test-binary")
	localPath := filepath.Join(t.TempDir(), "frogbot")
	require.NoError(t, os.WriteFile(localPath, content, 0o644))

	localDetails, err := fileutils.GetFileDetails(localPath, true)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.Header().Set("X-Checksum-Md5", localDetails.Checksum.Md5)
		w.Header().Set("X-Checksum-Sha1", localDetails.Checksum.Sha1)
		w.Header().Set("X-Checksum-Sha256", localDetails.Checksum.Sha256)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	require.NoError(t, VerifyLocalFileMatchesRemote(server.URL, localPath, ""))
}

func TestVerifyLocalFileMatchesRemoteMismatch(t *testing.T) {
	localPath := filepath.Join(t.TempDir(), "frogbot")
	require.NoError(t, os.WriteFile(localPath, []byte("content-a"), 0o644))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Checksum-Md5", "00000000000000000000000000000000")
		w.Header().Set("X-Checksum-Sha1", "0000000000000000000000000000000000000000")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := VerifyLocalFileMatchesRemote(server.URL, localPath, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}
