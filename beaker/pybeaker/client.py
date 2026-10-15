"""
HTTP API client for Beaker.

Provides methods for:
- System reservation (manual)
- System status queries
- Returning reservations
- Job submission and monitoring

Supports both Kerberos and username/password authentication.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth

from .config import BeakerConfig

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class SystemInfo:
    """Information about a Beaker system."""
    fqdn: str
    status: str
    condition: str
    owner: Optional[str] = None
    user: Optional[str] = None
    lab_controller: Optional[str] = None
    arch: list[str] = None  # type: ignore
    
    def __post_init__(self):
        if self.arch is None:
            self.arch = []


@dataclass
class Reservation:
    """Information about a system reservation."""
    system: str
    user: str
    start_time: Optional[datetime] = None
    finish_time: Optional[datetime] = None
    recipe_id: Optional[str] = None


@dataclass
class JobStatus:
    """Status of a Beaker job."""
    job_id: str
    status: str
    result: Optional[str] = None
    whiteboard: Optional[str] = None


class BeakerError(Exception):
    """Base exception for Beaker API errors."""
    pass


class BeakerAuthError(BeakerError):
    """Authentication failed."""
    pass


class BeakerNotFoundError(BeakerError):
    """Resource not found."""
    pass


class BeakerConflictError(BeakerError):
    """Resource conflict (e.g., system already reserved)."""
    pass


class BeakerClient:
    """HTTP API client for Beaker.
    
    Supports both Kerberos and password authentication.
    
    Example usage with password auth:
        >>> config = BeakerConfig(
        ...     hub_url="https://beaker.example.com/bkr",
        ...     auth_method="password",
        ...     username="user",
        ...     password="pass"
        ... )
        >>> client = BeakerClient(config)
        >>> 
        >>> # Check system status
        >>> info = client.get_system("machine.example.com")
        >>> print(f"System status: {info.status}")
    
    Example usage with Kerberos:
        >>> config = BeakerConfig(
        ...     hub_url="https://beaker.example.com/bkr",
        ...     auth_method="krbv",
        ...     krb_realm="IPA.REDHAT.COM"
        ... )
        >>> client = BeakerClient(config)
    """
    
    def __init__(self, config: Optional[BeakerConfig] = None):
        """Initialize the Beaker client.
        
        Args:
            config: BeakerConfig instance. If None, auto-detects configuration.
        """
        self.config = config or BeakerConfig.auto()
        self._session = requests.Session()
        self._session.verify = self.config.ssl_verify
        self._session.headers['Accept'] = 'application/json'
        self._setup_auth()
    
    def _setup_auth(self):
        """Configure authentication for the session."""
        if self.config.auth_method == "password":
            self._setup_password_auth()
        elif self.config.auth_method == "krbv":
            self._setup_kerberos_auth()
    
    def _setup_password_auth(self):
        """Set up password authentication using HTTP Basic Auth."""
        # Beaker supports HTTP Basic Auth (WWW-Authenticate: Basic realm="Beaker Web UI")
        self._session.auth = HTTPBasicAuth(
            self.config.username or "",
            self.config.password or ""
        )
        
        # Test the credentials by hitting the login endpoint
        login_url = f"{self.config.hub_url}/login"
        response = self._session.get(login_url, allow_redirects=True)
        
        if response.status_code == 401:
            raise BeakerAuthError("Invalid username or password")
        elif response.status_code != 200:
            raise BeakerAuthError(f"Password authentication failed: HTTP {response.status_code}")
        
        # Store the authenticated session cookies
        self._auth_cookies = self._session.cookies.copy()
    
    def _try_xmlrpc_login(self):
        """Try XML-RPC based authentication as fallback."""
        import html
        
        rpc_url = f"{self.config.hub_url}/RPC2"
        
        # Build XML-RPC request for auth.login_password
        username = html.escape(self.config.username or "")
        password = html.escape(self.config.password or "")
        
        rpc_body = f'''<?xml version="1.0"?>
<methodCall>
  <methodName>auth.login_password</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>'''
        
        try:
            response = self._session.post(
                rpc_url,
                data=rpc_body,
                headers={"Content-Type": "text/xml"},
                timeout=self.config.timeout,
            )
        except Exception:
            # Don't expose request body (contains password) in exception chain
            raise BeakerAuthError("XML-RPC authentication request failed") from None

        if response.status_code != 200:
            raise BeakerAuthError(f"Password authentication failed: {response.status_code}")

        if '<fault>' in response.text:
            # Extract actual error message
            fault_match = re.search(r'<faultString>.*?>(.*?)</string>', response.text)
            if not fault_match:
                fault_match = re.search(r'<string>(.*?)</string>', response.text)
            error_msg = fault_match.group(1) if fault_match else "Unknown error"
            
            if "Invalid username or password" in error_msg or "LoginException" in error_msg:
                raise BeakerAuthError(
                    "Password authentication failed. This Beaker instance may only support "
                    "Kerberos authentication. Try using: BEAKER_AUTH_METHOD=krbv (with kinit)"
                )
            raise BeakerAuthError(f"Password authentication failed: {error_msg}")
        
        # Store the authenticated session cookies
        self._auth_cookies = self._session.cookies.copy()
    
    def _setup_kerberos_auth(self):
        """Set up Kerberos authentication using requests_gssapi."""
        try:
            from requests_gssapi import HTTPSPNEGOAuth
        except ImportError:
            raise ImportError(
                "requests_gssapi is required for Kerberos authentication. "
                "Install it with: pip install requests-gssapi"
            )
        
        # Use SPNEGO auth for proper Kerberos negotiation
        self._session.auth = HTTPSPNEGOAuth()
        
        # Authenticate by hitting the login endpoint to get session cookie
        login_url = f"{self.config.hub_url}/login"
        response = self._session.get(login_url, allow_redirects=True)
        
        if response.status_code != 200:
            raise BeakerAuthError(f"Kerberos authentication failed: {response.status_code}")
        
        # Store the authenticated session cookies - they'll be used for subsequent requests
        # Clear the auth for RPC calls (use cookie instead)
        self._auth_cookies = self._session.cookies.copy()
    
    def _url(self, path: str) -> str:
        """Build full URL from path."""
        base = self.config.api_url.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        return base + path
    
    def _request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> requests.Response:
        """Make an HTTP request to the Beaker API.
        
        Args:
            method: HTTP method
            path: API path
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            BeakerAuthError: Authentication failed
            BeakerNotFoundError: Resource not found
            BeakerConflictError: Resource conflict
            BeakerError: Other API errors
        """
        kwargs.setdefault("timeout", self.config.timeout)
        
        response = self._session.request(method, self._url(path), **kwargs)
        
        if response.status_code == 401:
            raise BeakerAuthError("Authentication failed")
        elif response.status_code == 403:
            raise BeakerAuthError("Access denied")
        elif response.status_code == 404:
            raise BeakerNotFoundError(f"Resource not found: {path}")
        elif response.status_code == 409:
            raise BeakerConflictError(response.text)
        elif response.status_code >= 400:
            raise BeakerError(f"API error {response.status_code}: {response.text}")
        
        return response
    
    def whoami(self) -> str:
        """Get the current authenticated username.
        
        Returns:
            Username string
        """
        response = self._request("GET", "/users/+self")
        data = response.json()
        return data.get("user_name", data.get("username", ""))
    
    def get_system(self, fqdn: str) -> SystemInfo:
        """Get information about a system.
        
        Args:
            fqdn: Fully qualified domain name of the system
            
        Returns:
            SystemInfo object
        """
        response = self._request("GET", f"/systems/{fqdn}")
        data = response.json()
        
        return SystemInfo(
            fqdn=data.get("fqdn", fqdn),
            status=data.get("status", "Unknown"),
            condition=data.get("condition", "Unknown"),
            owner=data.get("owner", {}).get("user_name") if isinstance(data.get("owner"), dict) else data.get("owner"),
            user=data.get("user", {}).get("user_name") if isinstance(data.get("user"), dict) else data.get("user"),
            lab_controller=data.get("lab_controller_id"),
            arch=[a.get("arch", a) if isinstance(a, dict) else a for a in data.get("arch", [])],
        )
    
    def list_systems(
        self,
        status: Optional[str] = None,
        arch: Optional[str] = None,
        owner: Optional[str] = None,
        pool: Optional[str] = None,
        name_filter: Optional[str] = None,
        limit: int = 50,
    ) -> list[SystemInfo]:
        """List systems matching the given criteria.
        
        Args:
            status: Filter by status (e.g., 'Automated', 'Manual')
            arch: Filter by architecture (e.g., 'x86_64')
            owner: Filter by owner username
            pool: Filter by system pool name
            name_filter: Filter by FQDN pattern (e.g., '*jetson*')
            limit: Maximum number of results
            
        Returns:
            List of SystemInfo objects
        """
        params: dict[str, Any] = {"page_size": limit}
        
        # Build filter query
        filters = []
        if status:
            filters.append(f"status:{status}")
        if arch:
            filters.append(f"arch:{arch}")
        if owner:
            filters.append(f"owner:{owner}")
        if pool:
            filters.append(f"pool:{pool}")
        if name_filter:
            # Convert glob pattern to Beaker search format
            filters.append(f"fqdn:{name_filter}")
        
        if filters:
            params["q"] = " ".join(filters)
        
        response = self._request("GET", "/systems/", params=params)
        data = response.json()
        
        systems = []
        for item in data.get("entries", data if isinstance(data, list) else []):
            systems.append(SystemInfo(
                fqdn=item.get("fqdn", ""),
                status=item.get("status", "Unknown"),
                condition=item.get("condition", "Unknown"),
                owner=item.get("owner", {}).get("user_name") if isinstance(item.get("owner"), dict) else item.get("owner"),
            ))
        
        return systems
    
    def reserve_system(
        self,
        fqdn: str,
        duration: Optional[int] = None,
    ) -> Reservation:
        """Reserve a system manually.
        
        Args:
            fqdn: Fully qualified domain name of the system
            duration: Reservation duration in seconds (optional)
            
        Returns:
            Reservation object
            
        Raises:
            BeakerConflictError: System is not available for reservation
        """
        data = {}
        if duration:
            data["duration"] = duration
        
        response = self._request(
            "POST",
            f"/systems/{fqdn}/reservations/",
            json=data if data else None,
        )
        
        result = response.json() if response.text else {}
        
        return Reservation(
            system=fqdn,
            user=result.get("user", {}).get("user_name", self.config.username or ""),
            start_time=datetime.fromisoformat(result["start_time"]) if result.get("start_time") else None,
            finish_time=datetime.fromisoformat(result["finish_time"]) if result.get("finish_time") else None,
        )
    
    def return_reservation(self, fqdn: str) -> None:
        """Return (release) a system reservation.
        
        Args:
            fqdn: Fully qualified domain name of the system
        """
        self._request(
            "PATCH",
            f"/systems/{fqdn}/reservations/+current",
            json={"finish_time": "now"},
        )
    
    def extend_reservation(self, fqdn: str, seconds: int) -> None:
        """Extend the current reservation.
        
        Args:
            fqdn: Fully qualified domain name of the system
            seconds: Number of seconds to extend the reservation by
        """
        self._request(
            "PATCH",
            f"/systems/{fqdn}/reservations/+current",
            json={"extend": seconds},
        )
    
    def get_current_reservation(self, fqdn: str) -> Optional[Reservation]:
        """Get the current reservation for a system.
        
        Args:
            fqdn: Fully qualified domain name of the system
            
        Returns:
            Reservation object if system is reserved, None otherwise
        """
        try:
            response = self._request("GET", f"/systems/{fqdn}/reservations/+current")
            data = response.json()
            
            return Reservation(
                system=fqdn,
                user=data.get("user", {}).get("user_name", ""),
                start_time=datetime.fromisoformat(data["start_time"]) if data.get("start_time") else None,
                finish_time=datetime.fromisoformat(data["finish_time"]) if data.get("finish_time") else None,
                recipe_id=data.get("recipe_id"),
            )
        except BeakerNotFoundError:
            return None
    
    def submit_job(self, job_xml: str) -> str:
        """Submit a job to Beaker.

        Args:
            job_xml: Job XML string

        Returns:
            Job ID (e.g., "J:12345")
        """
        response = self._request(
            "POST", "/jobs",
            json={"ignore_missing_tasks": False, "xml": job_xml},
        )
        data = response.json()

        job_id = data.get("id") or data.get("t_id")
        if not job_id:
            raise BeakerError(f"Could not parse job ID from response: {data}")

        if isinstance(job_id, int):
            job_id = f"J:{job_id}"
        elif not str(job_id).startswith("J:"):
            job_id = f"J:{job_id}"

        return job_id
    
    def get_job_status(self, job_id: str) -> JobStatus:
        """Get the status of a job.
        
        Args:
            job_id: Job ID (e.g., "J:12345" or "12345")
            
        Returns:
            JobStatus object
        """
        # Extract numeric ID for URL
        numeric_id = job_id.replace("J:", "") if job_id.startswith("J:") else job_id
        display_id = f"J:{numeric_id}"
        
        response = self._request("GET", f"/jobs/{numeric_id}")
        data = response.json()
        
        return JobStatus(
            job_id=display_id,
            status=data.get("status", "Unknown"),
            result=data.get("result"),
            whiteboard=data.get("whiteboard"),
        )
    
    def list_jobs(
        self,
        owner: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 25,
    ) -> list[JobStatus]:
        """List jobs.

        Args:
            owner: Filter by owner username (default: current user)
            status: Filter by status (e.g., 'Running', 'Completed')
            limit: Maximum number of results

        Returns:
            List of JobStatus objects
        """
        params: dict[str, Any] = {"page": 1, "page_size": limit}
        if owner:
            params["owner"] = owner
        if status:
            params["status"] = status

        response = self._request("GET", "/jobs", params=params)
        data = response.json()

        jobs = []
        for item in data.get("items", []):
            job_id = item.get("t_id") or f"J:{item.get('id', '')}"
            jobs.append({
                "id": job_id,
                "status": item.get("status", "Unknown"),
                "result": item.get("result"),
                "whiteboard": item.get("whiteboard"),
            })

        return jobs
    
    def cancel_job(self, job_id: str, message: str = "Cancelled via API") -> None:
        """Cancel a job.

        Args:
            job_id: Job ID (e.g., "J:12345" or "12345")
            message: Cancellation message
        """
        numeric_id = job_id.replace("J:", "") if job_id.startswith("J:") else job_id
        self._request(
            "POST", f"/jobs/{numeric_id}/status",
            json={"status": "Cancelled", "msg": message},
        )
    
    def watch_job(
        self,
        job_id: str,
        callback: Optional[callable] = None,
        poll_interval: int = 30,
        timeout: Optional[int] = None,
    ) -> JobStatus:
        """Watch a job until it completes.
        
        Args:
            job_id: Job ID
            callback: Optional callback function(JobStatus) called on each poll
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait (None for no limit)
            
        Returns:
            Final JobStatus
        """
        import time
        
        start_time = time.time()
        terminal_statuses = {"Completed", "Cancelled", "Aborted"}
        
        while True:
            status = self.get_job_status(job_id)
            
            if callback:
                callback(status)
            
            if status.status in terminal_statuses:
                return status
            
            if timeout and (time.time() - start_time) >= timeout:
                raise TimeoutError(f"Job {job_id} did not complete within {timeout} seconds")
            
            time.sleep(poll_interval)
