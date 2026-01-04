"""
PR Change Detection System for Security Wiki Generator

This module handles GitHub API integration for PR diff extraction and
parsing of security-relevant modifications in pull requests.
Enhanced with proper rate limiting, error handling, and configuration management.
"""
import os
import re
import json
import logging
import requests
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime, timedelta
from dataclasses import dataclass
from threading import Lock

from api.config import settings

logger = logging.getLogger(__name__)


@dataclass
class RateLimitInfo:
    """GitHub API rate limit information"""
    limit: int
    remaining: int
    reset_time: datetime
    used: int
    
    @property
    def is_exhausted(self) -> bool:
        return self.remaining <= 0
    
    @property
    def reset_in_seconds(self) -> int:
        return max(0, int((self.reset_time - datetime.now()).total_seconds()))


class GitHubRateLimiter:
    """Rate limiter for GitHub API requests"""
    
    def __init__(self, requests_per_hour: int = 5000, requests_per_minute: int = 100):
        self.requests_per_hour = requests_per_hour
        self.requests_per_minute = requests_per_minute
        self.hourly_requests = []
        self.minute_requests = []
        self.lock = Lock()
        
    def can_make_request(self) -> bool:
        """Check if a request can be made without exceeding rate limits"""
        with self.lock:
            now = datetime.now()
            
            # Clean old requests
            self._clean_old_requests(now)
            
            # Check hourly limit
            if len(self.hourly_requests) >= self.requests_per_hour:
                return False
            
            # Check minute limit
            if len(self.minute_requests) >= self.requests_per_minute:
                return False
            
            return True
    
    def record_request(self):
        """Record a request for rate limiting"""
        with self.lock:
            now = datetime.now()
            self.hourly_requests.append(now)
            self.minute_requests.append(now)
    
    def wait_if_needed(self) -> float:
        """Wait if rate limit would be exceeded, return wait time"""
        if self.can_make_request():
            return 0.0
        
        with self.lock:
            now = datetime.now()
            self._clean_old_requests(now)
            
            # Calculate wait time
            wait_time = 0.0
            
            # Check minute limit
            if len(self.minute_requests) >= self.requests_per_minute:
                oldest_minute_request = min(self.minute_requests)
                wait_time = max(wait_time, 60 - (now - oldest_minute_request).total_seconds())
            
            # Check hourly limit
            if len(self.hourly_requests) >= self.requests_per_hour:
                oldest_hour_request = min(self.hourly_requests)
                wait_time = max(wait_time, 3600 - (now - oldest_hour_request).total_seconds())
            
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
            
            return wait_time
    
    def _clean_old_requests(self, now: datetime):
        """Remove old requests from tracking"""
        # Remove requests older than 1 hour
        hour_ago = now - timedelta(hours=1)
        self.hourly_requests = [req for req in self.hourly_requests if req > hour_ago]
        
        # Remove requests older than 1 minute
        minute_ago = now - timedelta(minutes=1)
        self.minute_requests = [req for req in self.minute_requests if req > minute_ago]


class GitHubAPIClient:
    """Enhanced GitHub API client with rate limiting and error handling"""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or (settings.github_token.get_secret_value() if settings.github_token else None)
        self.base_url = settings.github_api_base_url
        self.timeout = settings.github_timeout_seconds
        self.retry_attempts = settings.github_retry_attempts
        self.retry_backoff_factor = settings.github_retry_backoff_factor
        
        # Initialize rate limiter
        self.rate_limiter = GitHubRateLimiter(
            requests_per_hour=settings.github_requests_per_hour,
            requests_per_minute=settings.github_requests_per_minute
        )
        
        # Setup session
        self.session = requests.Session()
        self.session.timeout = self.timeout
        
        if self.token:
            self.session.headers.update({
                'Authorization': f'token {self.token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'ThreatLens-Security-Analyzer/1.0'
            })
            logger.info("GitHub API client initialized with authentication")
        else:
            self.session.headers.update({
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'ThreatLens-Security-Analyzer/1.0'
            })
            logger.warning("GitHub API client initialized without authentication - rate limits will be restrictive")
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make a rate-limited request with retry logic"""
        
        for attempt in range(self.retry_attempts):
            try:
                # Wait for rate limit if needed
                self.rate_limiter.wait_if_needed()
                
                # Make the request
                response = self.session.request(method, url, **kwargs)
                
                # Record the request for rate limiting
                self.rate_limiter.record_request()
                
                # Update rate limit info from response headers
                self._update_rate_limit_info(response)
                
                # Handle rate limit responses
                if response.status_code == 403 and 'rate limit' in response.text.lower():
                    rate_limit_reset = response.headers.get('X-RateLimit-Reset')
                    if rate_limit_reset:
                        reset_time = datetime.fromtimestamp(int(rate_limit_reset))
                        wait_time = (reset_time - datetime.now()).total_seconds()
                        if wait_time > 0:
                            logger.warning(f"GitHub API rate limit exceeded, waiting {wait_time:.1f} seconds")
                            time.sleep(min(wait_time, 3600))  # Max 1 hour wait
                            continue
                
                # Handle other 4xx/5xx errors with retry
                if response.status_code >= 400:
                    if attempt < self.retry_attempts - 1:
                        wait_time = self.retry_backoff_factor ** attempt
                        logger.warning(f"GitHub API request failed (attempt {attempt + 1}), retrying in {wait_time:.1f}s: {response.status_code}")
                        time.sleep(wait_time)
                        continue
                
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_backoff_factor ** attempt
                    logger.warning(f"GitHub API request exception (attempt {attempt + 1}), retrying in {wait_time:.1f}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    raise
        
        # If we get here, all retries failed
        raise requests.exceptions.RequestException(f"GitHub API request failed after {self.retry_attempts} attempts")
    
    def _update_rate_limit_info(self, response: requests.Response):
        """Update rate limit information from response headers"""
        try:
            if 'X-RateLimit-Limit' in response.headers:
                limit = int(response.headers['X-RateLimit-Limit'])
                remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                reset_timestamp = int(response.headers.get('X-RateLimit-Reset', 0))
                used = int(response.headers.get('X-RateLimit-Used', 0))
                
                reset_time = datetime.fromtimestamp(reset_timestamp)
                
                rate_limit_info = RateLimitInfo(
                    limit=limit,
                    remaining=remaining,
                    reset_time=reset_time,
                    used=used
                )
                
                if remaining < 100:  # Warn when getting low
                    logger.warning(f"GitHub API rate limit low: {remaining}/{limit} remaining, resets at {reset_time}")
                
        except (ValueError, KeyError) as e:
            logger.debug(f"Could not parse rate limit headers: {e}")
    
    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> Optional[Dict[str, Any]]:
        """
        Get PR information from GitHub API
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
            
        Returns:
            PR information dictionary or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
            response = self._make_request('GET', url)
            response.raise_for_status()
            
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Error fetching PR info for {owner}/{repo}#{pr_number}: {e}")
            return None
    
    def get_pr_files(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        """
        Get list of files changed in PR
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
            
        Returns:
            List of changed files with their details
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
            response = self._make_request('GET', url)
            response.raise_for_status()
            
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Error fetching PR files for {owner}/{repo}#{pr_number}: {e}")
            return []
    
    def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> Optional[str]:
        """
        Get PR diff in unified format
        
        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
            
        Returns:
            Diff content as string or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
            headers = {'Accept': 'application/vnd.github.v3.diff'}
            response = self._make_request('GET', url, headers=headers)
            response.raise_for_status()
            
            return response.text
            
        except requests.RequestException as e:
            logger.error(f"Error fetching PR diff for {owner}/{repo}#{pr_number}: {e}")
            return None
    
    def get_file_content(self, owner: str, repo: str, file_path: str, ref: str = "main") -> Optional[str]:
        """
        Get file content from repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to file
            ref: Git reference (branch, commit, tag)
            
        Returns:
            File content as string or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"
            params = {'ref': ref}
            response = self._make_request('GET', url, params=params)
            response.raise_for_status()
            
            content_data = response.json()
            if content_data.get('encoding') == 'base64':
                import base64
                return base64.b64decode(content_data['content']).decode('utf-8')
            else:
                return content_data.get('content', '')
                
        except requests.RequestException as e:
            logger.error(f"Error fetching file content for {owner}/{repo}/{file_path}: {e}")
            return None
    
    def check_repository_access(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Check if repository is accessible and get basic info
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Dictionary with access status and repository info
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}"
            response = self._make_request('GET', url)
            
            if response.status_code == 200:
                repo_data = response.json()
                return {
                    "accessible": True,
                    "private": repo_data.get("private", False),
                    "size": repo_data.get("size", 0),
                    "language": repo_data.get("language"),
                    "default_branch": repo_data.get("default_branch", "main"),
                    "archived": repo_data.get("archived", False),
                    "disabled": repo_data.get("disabled", False)
                }
            elif response.status_code == 404:
                return {
                    "accessible": False,
                    "error": "Repository not found or not accessible"
                }
            else:
                return {
                    "accessible": False,
                    "error": f"HTTP {response.status_code}: {response.text}"
                }
                
        except requests.RequestException as e:
            logger.error(f"Error checking repository access for {owner}/{repo}: {e}")
            return {
                "accessible": False,
                "error": f"Request failed: {str(e)}"
            }
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """
        Get current rate limit status
        
        Returns:
            Dictionary with rate limit information
        """
        try:
            url = f"{self.base_url}/rate_limit"
            response = self._make_request('GET', url)
            response.raise_for_status()
            
            return response.json()
            
        except requests.RequestException as e:
            logger.error(f"Error fetching rate limit status: {e}")
            return {"error": str(e)}


class PRChangeParser:
    """Parser for PR changes with security focus"""
    
    def __init__(self):
        # Security-relevant file patterns
        self.security_file_patterns = [
            r'.*auth.*\.(py|js|ts|java|go|rs|php)$',
            r'.*security.*\.(py|js|ts|java|go|rs|php)$',
            r'.*login.*\.(py|js|ts|java|go|rs|php)$',
            r'.*password.*\.(py|js|ts|java|go|rs|php)$',
            r'.*token.*\.(py|js|ts|java|go|rs|php)$',
            r'.*crypto.*\.(py|js|ts|java|go|rs|php)$',
            r'.*encrypt.*\.(py|js|ts|java|go|rs|php)$',
            r'.*config.*\.(py|js|ts|java|go|rs|php|json|yaml|yml)$',
            r'.*env.*\.(py|js|ts|java|go|rs|php)$',
            r'.*middleware.*\.(py|js|ts|java|go|rs|php)$',
            r'.*permission.*\.(py|js|ts|java|go|rs|php)$',
            r'.*role.*\.(py|js|ts|java|go|rs|php)$',
            r'.*api.*\.(py|js|ts|java|go|rs|php)$',
            r'.*database.*\.(py|js|ts|java|go|rs|php)$',
            r'.*model.*\.(py|js|ts|java|go|rs|php)$',
            r'.*schema.*\.(py|js|ts|java|go|rs|php|sql)$',
            r'.*migration.*\.(py|js|ts|java|go|rs|php|sql)$',
            r'.*dockerfile.*$',
            r'.*docker-compose.*\.(yml|yaml)$',
            r'.*requirements.*\.txt$',
            r'.*package.*\.json$',
            r'.*\.env.*$',
            r'.*\.config.*$'
        ]
        
        # Security-relevant code patterns
        self.security_code_patterns = {
            'authentication': [
                r'(login|signin|authenticate|verify)',
                r'(password|passwd|pwd)',
                r'(token|jwt|session)',
                r'(oauth|saml|ldap)',
                r'(hash|bcrypt|scrypt|pbkdf2)'
            ],
            'authorization': [
                r'(permission|authorize|access|role)',
                r'(admin|superuser|root)',
                r'(acl|rbac|policy)',
                r'(grant|deny|allow|restrict)'
            ],
            'data_handling': [
                r'(encrypt|decrypt|cipher)',
                r'(database|db|sql|query)',
                r'(serialize|deserialize|pickle)',
                r'(input|output|validation)',
                r'(sanitize|escape|filter)'
            ],
            'api_security': [
                r'(api|endpoint|route|handler)',
                r'(cors|csrf|xss)',
                r'(rate.?limit|throttle)',
                r'(header|cookie|param)',
                r'(request|response|middleware)'
            ],
            'crypto': [
                r'(key|secret|private|public)',
                r'(rsa|aes|des|sha|md5)',
                r'(random|entropy|nonce)',
                r'(certificate|cert|ssl|tls)',
                r'(signature|sign|verify)'
            ],
            'configuration': [
                r'(config|setting|env|environment)',
                r'(debug|production|development)',
                r'(port|host|url|endpoint)',
                r'(timeout|retry|limit)',
                r'(log|audit|monitor)'
            ]
        }
    
    def parse_pr_url(self, pr_url: str) -> Optional[Dict[str, str]]:
        """
        Parse PR URL to extract owner, repo, and PR number
        
        Args:
            pr_url: GitHub PR URL
            
        Returns:
            Dictionary with owner, repo, and pr_number or None if invalid
        """
        try:
            # Handle different GitHub URL formats
            patterns = [
                r'https://github\.com/([^/]+)/([^/]+)/pull/(\d+)',
                r'https://github\.com/([^/]+)/([^/]+)/pulls/(\d+)',
                r'github\.com/([^/]+)/([^/]+)/pull/(\d+)',
                r'github\.com/([^/]+)/([^/]+)/pulls/(\d+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, pr_url)
                if match:
                    return {
                        'owner': match.group(1),
                        'repo': match.group(2),
                        'pr_number': int(match.group(3))
                    }
            
            logger.error(f"Invalid PR URL format: {pr_url}")
            return None
            
        except Exception as e:
            logger.error(f"Error parsing PR URL: {e}")
            return None
    
    def analyze_changed_files(self, files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze changed files for security relevance
        
        Args:
            files: List of changed files from GitHub API
            
        Returns:
            Analysis results with security categorization
        """
        analysis = {
            'total_files': len(files),
            'security_relevant_files': [],
            'file_categories': {
                'authentication': [],
                'authorization': [],
                'data_handling': [],
                'api_security': [],
                'crypto': [],
                'configuration': []
            },
            'risk_indicators': [],
            'change_summary': {
                'additions': 0,
                'deletions': 0,
                'modifications': 0
            }
        }
        
        for file_info in files:
            filename = file_info.get('filename', '')
            status = file_info.get('status', '')
            additions = file_info.get('additions', 0)
            deletions = file_info.get('deletions', 0)
            patch = file_info.get('patch', '')
            
            # Update change summary
            analysis['change_summary']['additions'] += additions
            analysis['change_summary']['deletions'] += deletions
            if status == 'modified':
                analysis['change_summary']['modifications'] += 1
            
            # Check if file is security-relevant
            is_security_relevant = self._is_security_relevant_file(filename)
            
            if is_security_relevant:
                file_analysis = {
                    'filename': filename,
                    'status': status,
                    'additions': additions,
                    'deletions': deletions,
                    'security_categories': [],
                    'risk_level': 'low',
                    'security_patterns': []
                }
                
                # Analyze patch content for security patterns
                if patch:
                    security_patterns = self._analyze_patch_security(patch)
                    file_analysis['security_patterns'] = security_patterns
                    
                    # Categorize based on patterns found
                    for category, patterns in security_patterns.items():
                        if patterns:
                            file_analysis['security_categories'].append(category)
                            analysis['file_categories'][category].append(filename)
                
                # Determine risk level
                file_analysis['risk_level'] = self._assess_file_risk(file_analysis)
                
                analysis['security_relevant_files'].append(file_analysis)
                
                # Add to risk indicators if high risk
                if file_analysis['risk_level'] in ['high', 'critical']:
                    analysis['risk_indicators'].append({
                        'file': filename,
                        'risk': file_analysis['risk_level'],
                        'reason': f"Security-sensitive file with {additions + deletions} changes"
                    })
        
        return analysis
    
    def extract_security_changes(self, diff_content: str) -> Dict[str, Any]:
        """
        Extract security-relevant changes from diff content
        
        Args:
            diff_content: Unified diff content
            
        Returns:
            Dictionary with security change analysis
        """
        changes = {
            'security_additions': [],
            'security_deletions': [],
            'security_modifications': [],
            'risk_assessment': 'low',
            'patterns_found': {}
        }
        
        # Split diff into file sections
        file_sections = self._split_diff_by_files(diff_content)
        
        for file_path, file_diff in file_sections.items():
            if self._is_security_relevant_file(file_path):
                file_changes = self._analyze_file_diff(file_path, file_diff)
                
                changes['security_additions'].extend(file_changes['additions'])
                changes['security_deletions'].extend(file_changes['deletions'])
                changes['security_modifications'].extend(file_changes['modifications'])
                
                # Merge patterns found
                for category, patterns in file_changes['patterns'].items():
                    if category not in changes['patterns_found']:
                        changes['patterns_found'][category] = []
                    changes['patterns_found'][category].extend(patterns)
        
        # Assess overall risk
        changes['risk_assessment'] = self._assess_overall_risk(changes)
        
        return changes
    
    def _is_security_relevant_file(self, filename: str) -> bool:
        """Check if file is security-relevant based on patterns"""
        filename_lower = filename.lower()
        
        for pattern in self.security_file_patterns:
            if re.match(pattern, filename_lower):
                return True
        
        return False
    
    def _analyze_patch_security(self, patch: str) -> Dict[str, List[str]]:
        """Analyze patch content for security patterns"""
        patterns_found = {category: [] for category in self.security_code_patterns.keys()}
        
        # Split patch into lines and analyze added/modified lines
        lines = patch.split('\n')
        for line in lines:
            if line.startswith('+') and not line.startswith('+++'):
                # This is an added line
                line_content = line[1:].strip().lower()
                
                for category, patterns in self.security_code_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line_content):
                            patterns_found[category].append(pattern)
        
        # Remove duplicates
        for category in patterns_found:
            patterns_found[category] = list(set(patterns_found[category]))
        
        return patterns_found
    
    def _assess_file_risk(self, file_analysis: Dict[str, Any]) -> str:
        """Assess risk level for a file based on analysis"""
        risk_score = 0
        
        # Base risk from file type
        filename = file_analysis['filename'].lower()
        if any(pattern in filename for pattern in ['auth', 'security', 'password', 'token']):
            risk_score += 3
        elif any(pattern in filename for pattern in ['config', 'env', 'api']):
            risk_score += 2
        else:
            risk_score += 1
        
        # Risk from change volume
        total_changes = file_analysis['additions'] + file_analysis['deletions']
        if total_changes > 100:
            risk_score += 2
        elif total_changes > 50:
            risk_score += 1
        
        # Risk from security categories
        risk_score += len(file_analysis['security_categories'])
        
        # Risk from specific patterns
        high_risk_patterns = ['password', 'secret', 'key', 'token', 'admin', 'root']
        for patterns in file_analysis['security_patterns'].values():
            for pattern in patterns:
                if any(hrp in pattern for hrp in high_risk_patterns):
                    risk_score += 2
        
        # Convert score to risk level
        if risk_score >= 8:
            return 'critical'
        elif risk_score >= 6:
            return 'high'
        elif risk_score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def _split_diff_by_files(self, diff_content: str) -> Dict[str, str]:
        """Split unified diff into per-file sections"""
        file_sections = {}
        current_file = None
        current_content = []
        
        lines = diff_content.split('\n')
        for line in lines:
            if line.startswith('diff --git'):
                # Save previous file if exists
                if current_file and current_content:
                    file_sections[current_file] = '\n'.join(current_content)
                
                # Extract file path
                match = re.search(r'diff --git a/(.*?) b/', line)
                if match:
                    current_file = match.group(1)
                    current_content = [line]
                else:
                    current_file = None
                    current_content = []
            elif current_file:
                current_content.append(line)
        
        # Save last file
        if current_file and current_content:
            file_sections[current_file] = '\n'.join(current_content)
        
        return file_sections
    
    def _analyze_file_diff(self, file_path: str, file_diff: str) -> Dict[str, Any]:
        """Analyze diff for a specific file"""
        changes = {
            'additions': [],
            'deletions': [],
            'modifications': [],
            'patterns': {category: [] for category in self.security_code_patterns.keys()}
        }
        
        lines = file_diff.split('\n')
        line_number = 0
        
        for line in lines:
            if line.startswith('@@'):
                # Extract line number from hunk header
                match = re.search(r'@@\s*-\d+,?\d*\s*\+(\d+),?\d*\s*@@', line)
                if match:
                    line_number = int(match.group(1))
                continue
            
            if line.startswith('+') and not line.startswith('+++'):
                # Addition
                line_content = line[1:].strip()
                change_info = {
                    'file': file_path,
                    'line_number': line_number,
                    'content': line_content,
                    'type': 'addition'
                }
                changes['additions'].append(change_info)
                
                # Check for security patterns
                self._check_line_for_patterns(line_content, changes['patterns'])
                line_number += 1
                
            elif line.startswith('-') and not line.startswith('---'):
                # Deletion
                line_content = line[1:].strip()
                change_info = {
                    'file': file_path,
                    'line_number': line_number,
                    'content': line_content,
                    'type': 'deletion'
                }
                changes['deletions'].append(change_info)
                
                # Don't increment line number for deletions
                
            elif not line.startswith('\\'):
                # Context line
                line_number += 1
        
        return changes
    
    def _check_line_for_patterns(self, line_content: str, patterns_dict: Dict[str, List[str]]):
        """Check a line of code for security patterns"""
        line_lower = line_content.lower()
        
        for category, patterns in self.security_code_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line_lower):
                    patterns_dict[category].append({
                        'pattern': pattern,
                        'line': line_content
                    })
    
    def _assess_overall_risk(self, changes: Dict[str, Any]) -> str:
        """Assess overall risk level for all changes"""
        risk_score = 0
        
        # Risk from volume of security changes
        total_security_changes = (
            len(changes['security_additions']) +
            len(changes['security_deletions']) +
            len(changes['security_modifications'])
        )
        
        if total_security_changes > 50:
            risk_score += 3
        elif total_security_changes > 20:
            risk_score += 2
        elif total_security_changes > 5:
            risk_score += 1
        
        # Risk from pattern categories
        risk_score += len([cat for cat, patterns in changes['patterns_found'].items() if patterns])
        
        # Risk from specific high-risk patterns
        high_risk_categories = ['authentication', 'authorization', 'crypto']
        for category in high_risk_categories:
            if changes['patterns_found'].get(category):
                risk_score += 2
        
        # Convert to risk level
        if risk_score >= 8:
            return 'critical'
        elif risk_score >= 6:
            return 'high'
        elif risk_score >= 4:
            return 'medium'
        else:
            return 'low'


class PRChangeDetector:
    """Main class for PR change detection and analysis with enhanced GitHub integration"""
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_client = GitHubAPIClient(github_token)
        self.parser = PRChangeParser()
    
    def analyze_pr(self, pr_url: str) -> Dict[str, Any]:
        """
        Analyze a PR for security-relevant changes with enhanced error handling
        
        Args:
            pr_url: GitHub PR URL
            
        Returns:
            Comprehensive PR analysis with error handling and rate limit info
        """
        # Parse PR URL
        pr_info = self.parser.parse_pr_url(pr_url)
        if not pr_info:
            return {'error': 'Invalid PR URL format'}
        
        owner = pr_info['owner']
        repo = pr_info['repo']
        pr_number = pr_info['pr_number']
        
        # Check repository access first
        repo_access = self.github_client.check_repository_access(owner, repo)
        if not repo_access["accessible"]:
            return {
                'error': f'Repository not accessible: {repo_access.get("error", "Unknown error")}',
                'repository_info': repo_access
            }
        
        # Get PR information
        pr_data = self.github_client.get_pr_info(owner, repo, pr_number)
        if not pr_data:
            return {'error': 'Could not fetch PR information'}
        
        # Check if PR is in a valid state for analysis
        if pr_data.get('state') not in ['open', 'closed']:
            return {'error': f'PR is in invalid state: {pr_data.get("state")}'}
        
        # Get changed files
        changed_files = self.github_client.get_pr_files(owner, repo, pr_number)
        
        # Get PR diff
        diff_content = self.github_client.get_pr_diff(owner, repo, pr_number)
        
        # Analyze changes
        file_analysis = self.parser.analyze_changed_files(changed_files)
        
        security_changes = {}
        if diff_content:
            security_changes = self.parser.extract_security_changes(diff_content)
        
        # Get rate limit status for monitoring
        rate_limit_status = self.github_client.get_rate_limit_status()
        
        # Compile comprehensive analysis
        analysis = {
            'pr_info': {
                'url': pr_url,
                'number': pr_number,
                'title': pr_data.get('title', ''),
                'state': pr_data.get('state', ''),
                'author': pr_data.get('user', {}).get('login', ''),
                'created_at': pr_data.get('created_at', ''),
                'updated_at': pr_data.get('updated_at', ''),
                'base_branch': pr_data.get('base', {}).get('ref', ''),
                'head_branch': pr_data.get('head', {}).get('ref', ''),
                'mergeable': pr_data.get('mergeable'),
                'draft': pr_data.get('draft', False)
            },
            'repository': {
                'owner': owner,
                'name': repo,
                'full_name': f"{owner}/{repo}",
                'access_info': repo_access
            },
            'file_analysis': file_analysis,
            'security_changes': security_changes,
            'overall_assessment': self._generate_overall_assessment(file_analysis, security_changes),
            'api_info': {
                'rate_limit_status': rate_limit_status,
                'analysis_timestamp': datetime.now().isoformat()
            },
            'analyzed_at': datetime.now().isoformat()
        }
        
        return analysis
    
    def _generate_overall_assessment(self, file_analysis: Dict[str, Any], security_changes: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall security assessment for the PR"""
        # Determine overall risk level
        file_risk_levels = [f['risk_level'] for f in file_analysis['security_relevant_files']]
        security_risk = security_changes.get('risk_assessment', 'low')
        
        risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_file_risk = max([risk_priority.get(risk, 1) for risk in file_risk_levels] + [1])
        security_risk_score = risk_priority.get(security_risk, 1)
        
        overall_risk_score = max(max_file_risk, security_risk_score)
        overall_risk = {v: k for k, v in risk_priority.items()}[overall_risk_score]
        
        # Generate recommendations
        recommendations = []
        
        if file_analysis['security_relevant_files']:
            recommendations.append("Review security-relevant file changes carefully")
        
        if overall_risk in ['high', 'critical']:
            recommendations.append("Consider additional security review before merging")
            recommendations.append("Run security tests and vulnerability scans")
        
        if file_analysis['file_categories']['authentication']:
            recommendations.append("Verify authentication mechanisms are not weakened")
        
        if file_analysis['file_categories']['authorization']:
            recommendations.append("Check that authorization controls remain effective")
        
        if file_analysis['file_categories']['crypto']:
            recommendations.append("Ensure cryptographic implementations follow best practices")
        
        return {
            'overall_risk_level': overall_risk,
            'security_file_count': len(file_analysis['security_relevant_files']),
            'total_security_changes': len(security_changes.get('security_additions', [])) + 
                                    len(security_changes.get('security_deletions', [])),
            'recommendations': recommendations,
            'requires_security_review': overall_risk in ['medium', 'high', 'critical']
        }