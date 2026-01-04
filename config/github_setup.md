# GitHub API Configuration Guide

This guide explains how to configure GitHub API access for ThreatLens PR analysis functionality.

## Overview

ThreatLens uses the GitHub API to analyze pull requests for security implications. While the system can work without authentication, having a GitHub Personal Access Token significantly improves:

- **Rate Limits**: 5,000 requests/hour vs 60 requests/hour for unauthenticated requests
- **Private Repository Access**: Access to private repositories you have permissions for
- **Reliability**: Better error handling and retry mechanisms

## Creating a GitHub Personal Access Token

### Step 1: Navigate to GitHub Token Settings

1. Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token" → "Generate new token (classic)"

### Step 2: Configure Token Settings

**Token Name**: `ThreatLens Security Analyzer`

**Expiration**: Choose based on your security policy (90 days recommended)

**Scopes**: Select the following scopes based on your needs:

#### For Public Repositories Only:
- `public_repo` - Access public repositories

#### For Private Repositories:
- `repo` - Full control of private repositories
  - This includes: `repo:status`, `repo_deployment`, `public_repo`, `repo:invite`, `security_events`

#### Optional (for enhanced functionality):
- `read:org` - Read organization membership (if analyzing organization repositories)
- `read:user` - Read user profile information

### Step 3: Generate and Copy Token

1. Click "Generate token"
2. **Important**: Copy the token immediately - you won't be able to see it again
3. Store it securely (password manager recommended)

## Configuration

### Environment Variables

Add the following to your `.env` file:

```bash
# GitHub API Configuration
GITHUB_TOKEN=ghp_your_token_here
GITHUB_API_BASE_URL=https://api.github.com
GITHUB_REQUESTS_PER_HOUR=5000
GITHUB_REQUESTS_PER_MINUTE=100
GITHUB_TIMEOUT_SECONDS=30
GITHUB_RETRY_ATTEMPTS=3
GITHUB_RETRY_BACKOFF_FACTOR=2.0
```

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | None | GitHub Personal Access Token |
| `GITHUB_API_BASE_URL` | `https://api.github.com` | GitHub API base URL (for GitHub Enterprise) |
| `GITHUB_REQUESTS_PER_HOUR` | 5000 | Rate limit for requests per hour |
| `GITHUB_REQUESTS_PER_MINUTE` | 100 | Rate limit for requests per minute |
| `GITHUB_TIMEOUT_SECONDS` | 30 | Request timeout in seconds |
| `GITHUB_RETRY_ATTEMPTS` | 3 | Number of retry attempts on failure |
| `GITHUB_RETRY_BACKOFF_FACTOR` | 2.0 | Exponential backoff factor for retries |

## Rate Limits

### Authenticated Requests (with token):
- **5,000 requests per hour** per token
- **100 requests per minute** (configurable)
- Rate limits reset every hour

### Unauthenticated Requests:
- **60 requests per hour** per IP address
- Much more restrictive and not recommended for production

### Rate Limit Monitoring

ThreatLens automatically:
- Monitors rate limit usage
- Implements intelligent backoff when limits are approached
- Logs warnings when rate limits are low
- Provides rate limit status via `/github_status` endpoint

## GitHub Enterprise

For GitHub Enterprise installations:

```bash
GITHUB_API_BASE_URL=https://your-github-enterprise.com/api/v3
```

## Security Best Practices

### Token Security:
1. **Never commit tokens to version control**
2. **Use environment variables or secure secret management**
3. **Rotate tokens regularly** (every 90 days recommended)
4. **Use minimal required scopes**
5. **Monitor token usage** via GitHub settings

### Access Control:
1. **Limit token scopes** to minimum required permissions
2. **Use organization tokens** for organization repositories when possible
3. **Regularly audit token access** in GitHub settings
4. **Revoke unused tokens** immediately

## Troubleshooting

### Common Issues:

#### 1. "API rate limit exceeded"
- **Cause**: Too many requests without proper rate limiting
- **Solution**: Ensure `GITHUB_TOKEN` is configured correctly
- **Check**: `/github_status` endpoint for current rate limits

#### 2. "Repository not found or not accessible"
- **Cause**: Token doesn't have access to the repository
- **Solution**: Ensure token has appropriate scopes (`public_repo` or `repo`)
- **Check**: Repository visibility and your access permissions

#### 3. "Bad credentials"
- **Cause**: Invalid or expired token
- **Solution**: Generate a new token and update configuration
- **Check**: Token hasn't expired in GitHub settings

#### 4. "Not Found" for private repositories
- **Cause**: Token only has `public_repo` scope
- **Solution**: Generate new token with `repo` scope for private repository access

### Debugging Steps:

1. **Check GitHub API Status**:
   ```bash
   curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/rate_limit
   ```

2. **Test Repository Access**:
   ```bash
   curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/repos/owner/repo
   ```

3. **Check ThreatLens GitHub Status**:
   ```
   GET /github_status
   ```

4. **Verify Token Scopes**:
   ```bash
   curl -H "Authorization: token YOUR_TOKEN" -I https://api.github.com/user
   # Check X-OAuth-Scopes header
   ```

## Monitoring and Maintenance

### Regular Tasks:

1. **Monitor Rate Limit Usage**:
   - Check `/github_status` endpoint regularly
   - Set up alerts for low rate limits

2. **Token Rotation**:
   - Rotate tokens every 90 days
   - Update configuration with new tokens
   - Revoke old tokens

3. **Access Auditing**:
   - Review token access in GitHub settings
   - Remove unused or unnecessary tokens
   - Audit repository access permissions

### Health Checks:

ThreatLens provides several endpoints for monitoring GitHub API health:

- `/github_status` - GitHub API connectivity and rate limits
- `/health` - Overall system health including GitHub API status

## Support

For additional help:

1. **GitHub API Documentation**: https://docs.github.com/en/rest
2. **GitHub Token Documentation**: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
3. **ThreatLens Issues**: Create an issue in the ThreatLens repository

## Example Configuration

Complete example `.env` configuration:

```bash
# GitHub API Configuration
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678
GITHUB_API_BASE_URL=https://api.github.com
GITHUB_REQUESTS_PER_HOUR=4500  # Slightly below limit for safety
GITHUB_REQUESTS_PER_MINUTE=90   # Slightly below limit for safety
GITHUB_TIMEOUT_SECONDS=30
GITHUB_RETRY_ATTEMPTS=3
GITHUB_RETRY_BACKOFF_FACTOR=2.0

# Other ThreatLens configuration...
OPENAI_API_KEY=sk-your-openai-key
LLM_PROVIDER=openai
# ... rest of configuration
```