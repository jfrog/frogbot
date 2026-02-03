# Bitbucket Cloud Support - Implementation Guide

## Overview

Bitbucket Cloud support has been added to Frogbot. This document outlines the implementation details and how to use Frogbot with Bitbucket Cloud repositories.

## Implementation Summary

### Changes Made

1. **Added BitbucketCloud constant** ([utils/consts.go](utils/consts.go#L20))
   - Added `BitbucketCloud vcsProvider = "bitbucketCloud"` to the vcsProvider enum

2. **Updated provider detection** ([utils/params.go](utils/params.go#L741))
   - Modified `extractVcsProviderFromEnv()` to handle `bitbucketCloud` case
   - Updated error message to include `bitbucketCloud` as a valid provider option

3. **Configured output writer** ([utils/outputwriter/outputwriter.go](utils/outputwriter/outputwriter.go#L199))
   - Updated `GetCompatibleOutputWriter()` to return `SimplifiedOutput` for BitbucketCloud
   - Uses same output format as BitbucketServer due to API limitations

4. **Created integration tests** ([bitbucket_cloud_test.go](bitbucket_cloud_test.go))
   - Added test file following the pattern from BitbucketServer tests
   - Includes tests for scan-pull-request and scan-repository commands

## Configuration

### Environment Variables

To use Frogbot with Bitbucket Cloud, set the following environment variables:

```bash
# Required - VCS Provider
export JF_GIT_PROVIDER="bitbucketCloud"

# Required - Bitbucket Cloud Authentication
export JF_GIT_USERNAME="<your-bitbucket-username>"
export JF_GIT_TOKEN="<your-bitbucket-access-token>"

# Required - Repository Information
export JF_GIT_OWNER="<workspace-name>"      # Bitbucket workspace
export JF_GIT_REPO="<repository-slug>"

# Optional - API Endpoint (defaults to https://api.bitbucket.org/2.0)
export JF_GIT_API_ENDPOINT="https://api.bitbucket.org/2.0"

# Optional - Pull Request ID (for scan-pull-request command)
export JF_GIT_PULL_REQUEST_ID="<pr-number>"

# Required - JFrog Platform Credentials
export JF_URL="<jfrog-platform-url>"
export JF_ACCESS_TOKEN="<jfrog-access-token>"
# OR
export JF_USER="<jfrog-username>"
export JF_PASSWORD="<jfrog-password>"
```

### Bitbucket Cloud Access Token

To create an Access Token for authentication:

1. Go to Bitbucket Settings → Personal settings → Access tokens
2. Click "Create token"
3. Give it a label (e.g., "Frogbot")
4. Select required scopes:
   - **repository**: Read, Write
   - **pullrequest**: Read, Write
   - **webhook**: Read and write (if using webhooks)
5. Copy the generated token and use it as `JF_GIT_TOKEN`

## Usage Examples

### Scan Pull Request

```bash
# Set environment variables
export JF_GIT_PROVIDER="bitbucketCloud"
export JF_GIT_USERNAME="myusername"
export JF_GIT_TOKEN="app-password-here"
export JF_GIT_OWNER="myworkspace"
export JF_GIT_REPO="myrepo"
export JF_GIT_PULL_REQUEST_ID="42"
export JF_URL="https://mycompany.jfrog.io"
export JF_ACCESS_TOKEN="jfrog-token-here"

# Run scan
./frogbot scan-pull-request
```

### Scan Repository

```bash
# Set environment variables
export JF_GIT_PROVIDER="bitbucketCloud"
export JF_GIT_USERNAME="myusername"
export JF_GIT_TOKEN="app-password-here"
export JF_GIT_OWNER="myworkspace"
export JF_GIT_REPO="myrepo"
export JF_GIT_BASE_BRANCH="main"
export JF_URL="https://mycompany.jfrog.io"
export JF_ACCESS_TOKEN="jfrog-token-here"

# Run scan
./frogbot scan-repository
```

## Known Limitations

### Current froggit-go Implementation Limitations

The froggit-go library's BitbucketCloud client has some methods marked as not supported, though the Bitbucket Cloud API itself may support these features:

1. **Inline Review Comments**: `AddPullRequestReviewComments` returns `errBitbucketAddPullRequestReviewCommentsNotSupported`
   - However, the Bitbucket Cloud API v2.0 DOES support inline comments via the `inline` property with `from`, `to`, and `path` fields
   - This could potentially be implemented in froggit-go in the future

2. **Deleting PR Comments**: `DeletePullRequestComment` returns `errBitbucketDeletePullRequestComment`
   - However, the Bitbucket Cloud API v2.0 HAS a DELETE endpoint: `DELETE /repositories/{workspace}/{repo_slug}/pullrequests/{pull_request_id}/comments/{comment_id}`
   - This could potentially be implemented in froggit-go in the future
   - **Workaround**: Use `JF_AVOID_PREVIOUS_PR_COMMENTS_DELETION=true` to skip deletion attempts

3. **File Download**: `DownloadFileFromRepo` returns `errBitbucketDownloadFileFromRepoNotSupported`
   - File operations use repository cloning instead

### Actual Bitbucket Cloud API Limitations

4. **Labels**: Bitbucket Cloud API doesn't support PR labels

5. **GitHub-Specific Features**: These are GitHub-only APIs not available in Bitbucket Cloud:
   - Code scanning uploads (SARIF)
   - Organization secrets/variables management
   - Dependency graph SBOM submission
   - Some workflow/environment management features

**Note**: Items #1 and #2 appear to be froggit-go implementation gaps rather than actual API limitations. The Bitbucket Cloud REST API documentation shows these endpoints exist and are functional.

## Output Format

Bitbucket Cloud uses the **SimplifiedOutput** format (same as BitbucketServer) because:
- The Cloud API doesn't support adding review comments on specific lines
- The Cloud API doesn't support deleting comments
- Limited markdown rendering compared to GitHub/GitLab

This means vulnerability comments will be posted as general PR comments rather than inline code reviews.

## Testing

### Running Integration Tests

To run the integration tests:

1. Set up test environment variables:
```bash
export FROGBOT_TESTS_BB_CLOUD_TOKEN="<access-token>"
export FROGBOT_TESTS_BB_CLOUD_USERNAME="<username>"
```

2. Update test constants in [bitbucket_cloud_test.go](bitbucket_cloud_test.go):
   - `bitbucketCloudGitCloneUrl`: Your test repository clone URL
   - `bitbucketCloudWorkspace`: Your Bitbucket workspace name

3. Run tests:
```bash
go test -v -run TestBitbucketCloud
```

## Architecture Notes

### VCS Abstraction Layer

Frogbot uses the **froggit-go** library (`github.com/jfrog/froggit-go`) for all VCS operations. The BitbucketCloud client is fully implemented in froggit-go v1.21.0+, using the `ktrysmt/go-bitbucket` library for Bitbucket Cloud API v2.0 interactions.

Key components:
- **VcsClient Interface**: Defined in froggit-go, provides platform-agnostic VCS operations
- **BitbucketCloudClient**: Implementation in froggit-go that wraps Bitbucket Cloud API
- **Frogbot**: Consumes VcsClient interface without platform-specific code

### Authentication Flow

1. User provides `JF_GIT_USERNAME` and `JF_GIT_TOKEN` (Access Token)
2. Frogbot's `extractVcsProviderFromEnv()` detects `bitbucketCloud` provider
3. VCS client builder creates `BitbucketCloudClient` with username + token
4. Client uses HTTP Basic Auth for all API requests

## CI/CD Integration

### Bitbucket Pipelines

Example `bitbucket-pipelines.yml`:

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Frogbot Scan
          image: releases-docker.jfrog.io/frogbot:latest
          script:
            - export JF_GIT_PROVIDER="bitbucketCloud"
            - export JF_GIT_USERNAME="${BITBUCKET_WORKSPACE}"
            - export JF_GIT_TOKEN="${BITBUCKET_ACCESS_TOKEN}"
            - export JF_GIT_OWNER="${BITBUCKET_WORKSPACE}"
            - export JF_GIT_REPO="${BITBUCKET_REPO_SLUG}"
            - export JF_GIT_PULL_REQUEST_ID="${BITBUCKET_PR_ID}"
            - export JF_GIT_API_ENDPOINT="https://api.bitbucket.org/2.0"
            - export JF_URL="${JFROG_URL}"
            - export JF_ACCESS_TOKEN="${JFROG_TOKEN}"
            - frogbot scan-pull-request
```

Store secrets as repository variables:
- `BITBUCKET_ACCESS_TOKEN`
- `JFROG_URL`
- `JFROG_TOKEN`

## Troubleshooting

### Authentication Errors

**Problem**: `401 Unauthorized` errors

**Solution**: 
- Verify your Access Token has correct scopes (repository: Read/Write, pullrequest: Read/Write)
- Ensure `JF_GIT_USERNAME` matches your Bitbucket username exactly
- Check that the Access Token hasn't expired

### API Endpoint Issues

**Problem**: `404 Not Found` for repository operations

**Solution**:
- Verify `JF_GIT_OWNER` is the workspace name (not your username if different)
- Check `JF_GIT_REPO` is the repository slug (lowercase, dashes for spaces)
- Ensure API endpoint is set to `https://api.bitbucket.org/2.0`

### Comment Posting Failures

**Problem**: Comments not appearing on PRs

**Solution**:
- Verify the pull request ID is correct
- Check that the Access Token has "pullrequest: Write" scope
- Review Frogbot logs for specific API error messages

## Support

For issues specific to Bitbucket Cloud support:
1. Check the [known limitations](#known-limitations) section
2. Review [froggit-go issues](https://github.com/jfrog/froggit-go/issues) for API-related problems
3. Report bugs to [Frogbot issues](https://github.com/jfrog/frogbot/issues)

## References

- [Frogbot Documentation](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)
- [froggit-go Repository](https://github.com/jfrog/froggit-go)
- [Bitbucket Cloud API v2.0](https://developer.atlassian.com/cloud/bitbucket/rest/intro/)
- [Bitbucket Access Tokens](https://support.atlassian.com/bitbucket-cloud/docs/access-tokens/)
