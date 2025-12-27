# Git Field Auto-Detection - GitHub Actions

## Simple Mapping Table

| Git Field | Status | Source | Code Location |
|-----------|--------|--------|---------------|
| `JF_GIT_PROVIDER` | ✅ **Done** | Hardcoded: "github" | `utils.ts:62` |
| `JF_GIT_OWNER` | ✅ **Done** | `githubContext.repo.owner` | `utils.ts:63` |
| `JF_GIT_REPO` | ✅ **Done** | `githubContext.repo.repo` | `utils.ts:66` |
| `JF_GIT_PULL_REQUEST_ID` | ✅ **Done** | `githubContext.issue.number` | `utils.ts:68` |
| `JF_GIT_TOKEN` | 🔴 **TODO** | `process.env.GITHUB_TOKEN` | Need to add |
| `JF_GIT_BASE_BRANCH` | 🟡 **TODO** | `githubContext.payload.pull_request.base.ref` | Need to improve (line 77) |
| `JF_GIT_API_ENDPOINT` | 🟢 **TODO** | `process.env.GITHUB_API_URL` | Need to add |

## Available GitHub Actions Variables

### Environment Variables
```
GITHUB_TOKEN          → Use for JF_GIT_TOKEN
GITHUB_BASE_REF       → Use for JF_GIT_BASE_BRANCH (PRs)
GITHUB_REF_NAME       → Use for JF_GIT_BASE_BRANCH (push)
GITHUB_API_URL        → Use for JF_GIT_API_ENDPOINT
```

### Context Object
```typescript
githubContext.repo.owner                    → Already used for JF_GIT_OWNER
githubContext.repo.repo                     → Already used for JF_GIT_REPO
githubContext.issue.number                  → Already used for JF_GIT_PULL_REQUEST_ID
githubContext.payload.pull_request.base.ref → Use for JF_GIT_BASE_BRANCH
githubContext.apiUrl                        → Use for JF_GIT_API_ENDPOINT (fallback)
```

## Implementation Priority

### 🔴 High Priority: `JF_GIT_TOKEN`
**Why**: Most commonly needed, biggest user pain point
**Code**:
```typescript
const token = process.env.JF_GIT_TOKEN || process.env.GITHUB_TOKEN;
if (!token) throw new Error('GitHub token not found');
core.exportVariable('JF_GIT_TOKEN', token);
```

### 🟡 Medium Priority: `JF_GIT_BASE_BRANCH`
**Why**: Currently has buggy implementation
**Code**:
```typescript
if (!process.env.JF_GIT_BASE_BRANCH) {
    const baseBranch = eventName.includes('pull_request')
        ? githubContext.payload.pull_request?.base?.ref || process.env.GITHUB_BASE_REF
        : process.env.GITHUB_REF_NAME || githubContext.ref.replace('refs/heads/', '');
    core.exportVariable('JF_GIT_BASE_BRANCH', baseBranch);
}
```

### 🟢 Low Priority: `JF_GIT_API_ENDPOINT`
**Why**: Nice to have for GitHub Enterprise
**Code**:
```typescript
if (!process.env.JF_GIT_API_ENDPOINT) {
    const apiUrl = process.env.GITHUB_API_URL || githubContext.apiUrl || 'https://api.github.com';
    core.exportVariable('JF_GIT_API_ENDPOINT', apiUrl);
}
```

## Result

**Before**: User provides 5-7 environment variables  
**After**: User provides 2 environment variables (JFrog credentials only)

**Improvement**: 60-70% reduction in required configuration! 🎉


