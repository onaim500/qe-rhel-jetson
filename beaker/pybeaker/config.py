"""
Configuration management for Beaker client.

Supports loading from:
- Environment variables
- Config file (~/.beaker_client/config or /etc/beaker/client.conf)
- Direct initialization
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional
import configparser


AuthMethod = Literal["password", "krbv", "none"]


@dataclass
class BeakerConfig:
    """Configuration for Beaker client.
    
    Attributes:
        hub_url: URL of the Beaker server (without trailing slash)
        auth_method: Authentication method ('password', 'krbv', or 'none')
        username: Username for password authentication
        password: Password for password authentication
        krb_realm: Kerberos realm for krbv authentication
        ssl_verify: Whether to verify SSL certificates
        timeout: Request timeout in seconds
    """
    hub_url: str = ""
    auth_method: AuthMethod = "password"
    username: Optional[str] = None
    password: Optional[str] = None
    krb_realm: Optional[str] = None
    ssl_verify: bool = True
    timeout: int = 30
    
    # Default config file locations
    _config_paths: list[Path] = field(default_factory=lambda: [
        Path.home() / ".beaker_client" / "config",
        Path("/etc/beaker/client.conf"),
    ])
    
    @classmethod
    def from_env(cls) -> "BeakerConfig":
        """Load configuration from environment variables.
        
        Environment variables:
            BEAKER_HUB_URL: URL of the Beaker server
            BEAKER_AUTH_METHOD: 'password' or 'krbv'
            BEAKER_USERNAME: Username for password auth
            BEAKER_PASSWORD: Password for password auth
            BEAKER_KRB_REALM: Kerberos realm
            BEAKER_SSL_VERIFY: '0' or 'false' to disable SSL verification
        """
        ssl_verify_env = os.environ.get("BEAKER_SSL_VERIFY", "1").lower()
        ssl_verify = ssl_verify_env not in ("0", "false", "no")
        
        return cls(
            hub_url=os.environ.get("BEAKER_HUB_URL", ""),
            auth_method=os.environ.get("BEAKER_AUTH_METHOD", "password"),  # type: ignore
            username=os.environ.get("BEAKER_USERNAME"),
            password=os.environ.get("BEAKER_PASSWORD"),
            krb_realm=os.environ.get("BEAKER_KRB_REALM"),
            ssl_verify=ssl_verify,
        )
    
    @classmethod
    def from_file(cls, path: Optional[Path] = None) -> "BeakerConfig":
        """Load configuration from a config file.
        
        Args:
            path: Path to config file. If None, searches default locations.
        
        Returns:
            BeakerConfig instance
            
        Raises:
            FileNotFoundError: If no config file is found
        """
        config = cls()
        
        if path is None:
            for default_path in config._config_paths:
                if default_path.exists():
                    path = default_path
                    break
        
        if path is None or not path.exists():
            raise FileNotFoundError(
                f"No Beaker config file found. Searched: {config._config_paths}"
            )
        
        # Parse the config file (Python-style key = value)
        parser = configparser.ConfigParser()
        # Read as a fake section since Beaker config has no sections
        config_text = f"[beaker]\n{path.read_text()}"
        parser.read_string(config_text)
        
        section = parser["beaker"]
        
        return cls(
            hub_url=section.get("HUB_URL", "").strip('"\''),
            auth_method=section.get("AUTH_METHOD", "password").strip('"\''),  # type: ignore
            username=section.get("USERNAME", "").strip('"\'') or None,
            password=section.get("PASSWORD", "").strip('"\'') or None,
            krb_realm=section.get("KRB_REALM", "").strip('"\'') or None,
        )
    
    @classmethod
    def auto(cls) -> "BeakerConfig":
        """Auto-detect configuration.
        
        Priority:
        1. Environment variables (if BEAKER_HUB_URL is set)
        2. Config file
        """
        if os.environ.get("BEAKER_HUB_URL"):
            return cls.from_env()
        
        try:
            return cls.from_file()
        except FileNotFoundError:
            return cls.from_env()
    
    def validate(self) -> list[str]:
        """Validate the configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        if not self.hub_url:
            errors.append("hub_url is required")
        
        if self.auth_method == "password":
            if not self.username:
                errors.append("username is required for password authentication")
            if not self.password:
                errors.append("password is required for password authentication")
        elif self.auth_method == "krbv":
            if not self.krb_realm:
                errors.append("krb_realm is required for Kerberos authentication")
        
        return errors
    
    @property
    def api_url(self) -> str:
        """Get the base API URL."""
        return self.hub_url.rstrip("/") + "/bkr-api"

