#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import tempfile
import webbrowser
import http.server
import socketserver
import urllib.parse
import threading
import time
from datetime import datetime, timedelta
import logging
import argparse
import configparser
import base64

# Azure authentication imports
try:
    import requests
    from azure.identity import (
        InteractiveBrowserCredential,
        DeviceCodeCredential,
        ClientSecretCredential,
        DefaultAzureCredential
    )
    from azure.core.exceptions import ClientAuthenticationError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    print("Error: Azure libraries not available. Install with:")
    print("pip install azure-identity requests")
    sys.exit(1)

# Configuration
CONFIG_DIR = os.path.expanduser('~/.cassandra')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'jwt_config')
TOKEN_CACHE_FILE = os.path.join(CONFIG_DIR, 'jwt_token_cache')
LOG_FILE = os.path.join(CONFIG_DIR, 'cqlsh_token.log')

# Default configuration
DEFAULT_CONFIG = {
    'azure': {
        'client_id': '',
        'client_secret': '',  # Optional - for custom API scopes
        'tenant_id': '',
        'scope': 'openid profile email',
        'redirect_uri': 'http://localhost:8080/callback',
        'authority': 'https://login.microsoftonline.com/',
        'authentication_method': 'interactive'  # interactive, device_code, client_credentials
    },
    'cassandra': {
        'host': 'localhost',
        'port': '9042',
        'ssl': 'false',
        'username': '',
        'keyspace': ''
    },
    'jwt': {
        'use_token_as_username': 'false',
        'username_claim': 'preferred_username',
        'token_format': 'raw'  # 'raw' or 'bearer'
    },
    'logging': {
        'level': 'INFO',
        'file': LOG_FILE
    }
}

class AzureJWTAuthManager:
    """Manages Azure JWT authentication with multiple flow support"""

#     def __init__(self, config_file=CONFIG_FILE):
#         self.config_file = config_file
#         self.config = self._load_config()
#         self.token_cache = {}
#
#         # Ensure config directory exists
#         os.makedirs(CONFIG_DIR, exist_ok=True)
#
#         # Set up logging
#         log_level = getattr(logging, self.config.get('logging', 'level', fallback='INFO'))
#         log_file = self.config.get('logging', 'file', fallback=LOG_FILE)
#
#         logging.basicConfig(
#             level=log_level,
#             format='%(asctime)s - %(levelname)s - %(message)s',
#             handlers=[
#                 logging.FileHandler(log_file),
#                 logging.StreamHandler()
#             ]
#         )
#         self.logger = logging.getLogger(__name__)

    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        self.config = self._load_config()
        self.token_cache = {}

        # Ensure config directory exists
        os.makedirs(CONFIG_DIR, exist_ok=True)

        # Set up logging
        log_level = getattr(logging, self.config.get('logging', 'level', fallback='INFO'))
        log_file = self.config.get('logging', 'file', fallback=LOG_FILE)

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

        logging.getLogger('msal').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)

        self.logger = logging.getLogger(__name__)

    def _load_config(self):
        """Load configuration from file or create default"""
        config = configparser.ConfigParser()

        if os.path.exists(self.config_file):
            config.read(self.config_file)
        else:
            # Create default config
            for section, options in DEFAULT_CONFIG.items():
                config.add_section(section)
                for key, value in options.items():
                    config.set(section, key, str(value))

            self._save_config(config)
            self.logger.info(f"Created default configuration at {self.config_file}")
            self.logger.info("Please run --setup to configure your Azure AD settings")

        return config

    def _save_config(self, config):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            config.write(f)
        os.chmod(self.config_file, 0o600)

    def _load_token_cache(self):
        """Load cached tokens"""
        try:
            if os.path.exists(TOKEN_CACHE_FILE):
                with open(TOKEN_CACHE_FILE, 'r') as f:
                    self.token_cache = json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load token cache: {e}")
            self.token_cache = {}

    def _save_token_cache(self):
        """Save token cache"""
        try:
            with open(TOKEN_CACHE_FILE, 'w') as f:
                json.dump(self.token_cache, f, indent=2, default=str)
            os.chmod(TOKEN_CACHE_FILE, 0o600)
        except Exception as e:
            self.logger.warning(f"Failed to save token cache: {e}")

    def _is_token_expired(self, token_info):
        """Check if token is expired"""
        if not token_info or 'expires_at' not in token_info:
            return True

        try:
            expires_at_str = str(token_info['expires_at'])
            # Handle different date formats
            if expires_at_str.replace('.', '').isdigit():
                # It's a timestamp
                expires_at = datetime.fromtimestamp(float(expires_at_str))
            else:
                # It's an ISO format string
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))

            return datetime.now() + timedelta(minutes=5) >= expires_at
        except Exception as e:
            self.logger.warning(f"Could not parse token expiration: {e}")
            return True

    def _get_credential(self):
        """Get appropriate Azure credential based on configuration"""
        client_id = self.config.get('azure', 'client_id')
        client_secret = self.config.get('azure', 'client_secret', fallback='')
        tenant_id = self.config.get('azure', 'tenant_id', fallback='common')
        auth_method = self.config.get('azure', 'authentication_method', fallback='interactive')

        if not client_id:
            raise Exception("Azure client_id not configured. Run --setup to configure.")

        if auth_method == 'client_credentials' and client_secret:
            self.logger.info("Using client credentials flow")
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        elif auth_method == 'device_code':
            self.logger.info("Using device code flow")
            return DeviceCodeCredential(
                client_id=client_id,
                tenant_id=tenant_id
            )
        elif client_secret:
            # If client secret is available, prefer it for custom API scopes
            self.logger.info("Using client secret credential for custom API scope")
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            # Use interactive browser flow
            self.logger.info("Using interactive browser flow")
            redirect_uri = self.config.get('azure', 'redirect_uri', fallback='http://localhost:8080/callback')
            return InteractiveBrowserCredential(
                client_id=client_id,
                tenant_id=tenant_id,
                redirect_uri=redirect_uri
            )

    def get_jwt_token(self, force_refresh=False):
        """Get JWT token via configured authentication method"""
        if not AZURE_AVAILABLE:
            raise Exception("Azure libraries not installed")

        scope = self.config.get('azure', 'scope')
        client_id = self.config.get('azure', 'client_id')
        tenant_id = self.config.get('azure', 'tenant_id')

        # Check cache first (unless forcing refresh)
        if not force_refresh:
            self._load_token_cache()
            cache_key = f"{client_id}_{tenant_id}_{scope}"

            if (cache_key in self.token_cache and
                not self._is_token_expired(self.token_cache[cache_key])):
                self.logger.info("Using cached JWT token")
                return self.token_cache[cache_key]['access_token']

        try:
            self.logger.info("Acquiring new Azure token...")
            credential = self._get_credential()
            token_response = credential.get_token(scope)

            # Handle different expiration date formats
            expires_at = token_response.expires_on
            if isinstance(expires_at, (int, float)):
                # Convert timestamp to datetime, then to ISO format
                expires_at_dt = datetime.fromtimestamp(expires_at)
                expires_at_iso = expires_at_dt.isoformat()
            elif hasattr(expires_at, 'isoformat'):
                # It's already a datetime object
                expires_at_iso = expires_at.isoformat()
            else:
                # Fallback - use string representation
                expires_at_iso = str(expires_at)

            # Cache the token
            cache_key = f"{client_id}_{tenant_id}_{scope}"
            token_info = {
                'access_token': token_response.token,
                'expires_at': expires_at_iso,
                'scope': scope,
                'client_id': client_id,
                'tenant_id': tenant_id
            }

            self.token_cache[cache_key] = token_info
            self._save_token_cache()

            self.logger.info("Azure authentication successful")
            return token_response.token

        except ClientAuthenticationError as e:
            self.logger.error(f"Azure authentication failed: {e}")
            # Try device code flow as fallback if interactive flow failed
            if 'interactive' in str(e).lower():
                self.logger.info("Trying device code flow as fallback...")
                return self._device_code_fallback()
            raise Exception(f"Authentication failed: {e}")
        except Exception as e:
            self.logger.error(f"Failed to get Azure token: {e}")
            raise Exception(f"Token acquisition failed: {e}")

    def _device_code_fallback(self):
        """Fallback to device code authentication"""
        client_id = self.config.get('azure', 'client_id')
        tenant_id = self.config.get('azure', 'tenant_id', fallback='common')
        scope = self.config.get('azure', 'scope')

        try:
            credential = DeviceCodeCredential(
                client_id=client_id,
                tenant_id=tenant_id
            )

            token_response = credential.get_token(scope)

            # Handle expiration date format
            expires_at = token_response.expires_on
            if isinstance(expires_at, (int, float)):
                expires_at_iso = datetime.fromtimestamp(expires_at).isoformat()
            elif hasattr(expires_at, 'isoformat'):
                expires_at_iso = expires_at.isoformat()
            else:
                expires_at_iso = str(expires_at)

            # Cache the token
            cache_key = f"{client_id}_{tenant_id}_{scope}"
            token_info = {
                'access_token': token_response.token,
                'expires_at': expires_at_iso,
                'scope': scope,
                'client_id': client_id,
                'tenant_id': tenant_id
            }

            self.token_cache[cache_key] = token_info
            self._save_token_cache()

            return token_response.token

        except Exception as e:
            raise Exception(f"Device code authentication failed: {e}")

    def get_username_from_token(self, token):
        """Extract username from JWT token"""
        try:
            # Decode JWT token (without verification for username extraction)
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode payload
            payload = parts[1]
            # Add padding if needed
            payload += '=' * (4 - len(payload) % 4)
            decoded = json.loads(base64.b64decode(payload))

            username_claim = self.config.get('jwt', 'username_claim', fallback='preferred_username')
            username = decoded.get(username_claim)

            # Try alternative claims if preferred username is not found
            if not username:
                for claim in ['upn', 'email', 'unique_name', 'name']:
                    username = decoded.get(claim)
                    if username:
                        break

            self.logger.debug(f"Extracted username: {username} from claim: {username_claim}")
            return username

        except Exception as e:
            self.logger.warning(f"Failed to extract username from token: {e}")
            return None

    def clear_token_cache(self):
        """Clear all cached tokens"""
        try:
            if os.path.exists(TOKEN_CACHE_FILE):
                os.remove(TOKEN_CACHE_FILE)
            self.token_cache = {}
            self.logger.info("Token cache cleared")
        except Exception as e:
            self.logger.error(f"Failed to clear token cache: {e}")

def setup_configuration():
    """Interactive setup for configuration"""
    print("Azure JWT Authentication Setup for cqlsh")
    print("=" * 50)

    config = configparser.ConfigParser()

    # Azure configuration
    config.add_section('azure')
    print("\n1. Azure AD Configuration:")
    client_id = input("Azure AD Application (Client) ID: ").strip()
    tenant_id = input("Azure AD Tenant ID [common]: ").strip() or 'common'

    # Ask about authentication method
    print("\nAuthentication method options:")
    print("  1. Interactive browser (default)")
    print("  2. Device code (for headless environments)")
    print("  3. Client credentials (service principal)")
    auth_choice = input("Choose method (1-3) [1]: ").strip() or '1'

    auth_methods = {
        '1': 'interactive',
        '2': 'device_code',
        '3': 'client_credentials'
    }
    auth_method = auth_methods.get(auth_choice, 'interactive')

    client_secret = ''
    if auth_choice == '3' or input("Do you have a client secret for custom API scopes? (y/n) [n]: ").strip().lower() in ['y', 'yes']:
        client_secret = input("Azure AD Client Secret: ").strip()

    # Scope configuration
    print("\nScope options:")
    print("  1. Standard Microsoft Graph scopes (openid profile email)")
    print("  2. Custom API scope (e.g., api://your-app-id/.default)")
    scope_choice = input("Choose scope type (1-2) [1]: ").strip() or '1'

    if scope_choice == '2':
        scope = input("Custom API scope (must end with /.default): ").strip()
        if not scope.endswith('/.default'):
            print("Warning: Custom API scopes for client credentials must end with /.default")
            scope = scope + '/.default'
    else:
        scope = 'openid profile email'

    redirect_uri = input("Redirect URI [http://localhost:8080/callback]: ").strip() or 'http://localhost:8080/callback'

    config.set('azure', 'client_id', client_id)
    config.set('azure', 'client_secret', client_secret)
    config.set('azure', 'tenant_id', tenant_id)
    config.set('azure', 'scope', scope)
    config.set('azure', 'redirect_uri', redirect_uri)
    config.set('azure', 'authority', 'https://login.microsoftonline.com/')
    config.set('azure', 'authentication_method', auth_method)

    # Cassandra configuration
    config.add_section('cassandra')
    print("\n2. Cassandra Configuration:")
    host = input("Cassandra Host [localhost]: ").strip() or 'localhost'
    port = input("Cassandra Port [9042]: ").strip() or '9042'
    ssl = input("Use SSL? (y/n) [n]: ").strip().lower() in ['y', 'yes']
    keyspace = input("Default Keyspace (optional): ").strip()

    config.set('cassandra', 'host', host)
    config.set('cassandra', 'port', port)
    config.set('cassandra', 'ssl', str(ssl).lower())
    config.set('cassandra', 'keyspace', keyspace)
    config.set('cassandra', 'username', '')

    # JWT configuration
    config.add_section('jwt')
    print("\n3. JWT Configuration:")
    use_token_as_username = input("Use entire JWT token as username? (y/n) [n]: ").strip().lower() in ['y', 'yes']

    if not use_token_as_username:
        username_claim = input("Username claim in JWT [preferred_username]: ").strip() or 'preferred_username'
    else:
        username_claim = 'preferred_username'

    token_format = input("Token format (raw/bearer) [raw]: ").strip() or 'raw'

    config.set('jwt', 'use_token_as_username', str(use_token_as_username).lower())
    config.set('jwt', 'username_claim', username_claim)
    config.set('jwt', 'token_format', token_format)

    # Logging configuration
    config.add_section('logging')
    log_level = input("Log level (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip() or 'INFO'
    config.set('logging', 'level', log_level)
    config.set('logging', 'file', LOG_FILE)

    # Save configuration
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)
    os.chmod(CONFIG_FILE, 0o600)

    print(f"\nConfiguration saved to: {CONFIG_FILE}")
    print("You can now use cqlsh-token to authenticate!")

def launch_cqlsh_with_token(args, token, username=None):
    """Launch cqlsh with JWT token"""
    auth_manager = AzureJWTAuthManager()
    config = auth_manager.config

    # Build cqlsh command
    cmd = ['cqlsh']

    # Add host and port if not specified
    host_specified = False
    for i, arg in enumerate(args):
        if not arg.startswith('-') and i == 0:
            host_specified = True
            break

    if not host_specified:
        host = config.get('cassandra', 'host', fallback='localhost')
        port = config.get('cassandra', 'port', fallback='9042')
        cmd.extend([host, port])

    # Add existing arguments
    cmd.extend(args)

    # Handle authentication
    use_token_as_username = config.getboolean('jwt', 'use_token_as_username', fallback=False)
    token_format = config.get('jwt', 'token_format', fallback='raw')

    if use_token_as_username:
        # Use token as username
        token_to_use = f"Bearer {token}" if token_format == 'bearer' else token
        if not any(arg in ['-u', '--username'] for arg in cmd):
            cmd.extend(['-u', token_to_use])
        if not any(arg in ['-p', '--password'] for arg in cmd):
            cmd.extend(['-p', ''])  # Empty password
    else:
        # Use extracted username and token as password
        if not username:
            username = auth_manager.get_username_from_token(token)
            if not username:
                username = config.get('cassandra', 'username', fallback='azure_user')

        token_to_use = f"Bearer {token}" if token_format == 'bearer' else token

        if not any(arg in ['-u', '--username'] for arg in cmd):
            cmd.extend(['-u', username])
        if not any(arg in ['-p', '--password'] for arg in cmd):
            cmd.extend(['-p', token_to_use])

    # Add SSL if configured and not already specified
    if (config.getboolean('cassandra', 'ssl', fallback=False) and
        '--ssl' not in cmd):
        cmd.append('--ssl')

    # Add default keyspace if configured
    default_keyspace = config.get('cassandra', 'keyspace', fallback='')
    if (default_keyspace and
        not any(arg in ['-k', '--keyspace'] for arg in cmd)):
        cmd.extend(['-k', default_keyspace])

    print("Launching cqlsh with JWT authentication...")
    print(f"Connecting as user: {username if not use_token_as_username else '[JWT token]'}")

    # Create a safe command display (hide sensitive info)
    safe_cmd = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            safe_cmd.append('[HIDDEN]')
            skip_next = False
        elif arg in ['-u', '--username', '-p', '--password']:
            safe_cmd.append(arg)
            skip_next = True
        else:
            safe_cmd.append(arg)

    print(f"Command: {' '.join(safe_cmd)}")

    try:
        # Execute cqlsh
        os.execvp('cqlsh', cmd)
    except FileNotFoundError:
        print("Error: cqlsh not found in PATH")
        print("Make sure Cassandra is installed and cqlsh is available")
        print("You can install cqlsh via: pip install cqlsh")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching cqlsh: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Browser-based Azure authentication wrapper for cqlsh',
        epilog='All other arguments are passed through to cqlsh'
    )

    parser.add_argument('--setup', action='store_true',
                       help='Run interactive configuration setup')
    parser.add_argument('--show-token', action='store_true',
                       help='Display current JWT token')
    parser.add_argument('--clear-cache', action='store_true',
                       help='Clear cached tokens')
    parser.add_argument('--config',
                       help='Use alternative config file')
    parser.add_argument('--username', '-u',
                       help='Override username (token still used as password)')
    parser.add_argument('--force-refresh', action='store_true',
                       help='Force token refresh (ignore cache)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')

    # Parse known args to allow pass-through to cqlsh
    args, cqlsh_args = parser.parse_known_args()

    # Handle debug flag
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle special commands
    if args.setup:
        setup_configuration()
        return

    if args.clear_cache:
        auth_manager = AzureJWTAuthManager(args.config if args.config else CONFIG_FILE)
        auth_manager.clear_token_cache()
        print("Token cache cleared")
        return

    # Initialize auth manager with custom config if specified
    config_file = args.config if args.config else CONFIG_FILE
    auth_manager = AzureJWTAuthManager(config_file)

    if args.show_token:
        try:
            token = auth_manager.get_jwt_token(force_refresh=args.force_refresh)
            print(f"JWT Token: {token[:50]}...{token[-20:] if len(token) > 70 else ''}")

            # Try to extract and show username
            username = auth_manager.get_username_from_token(token)
            if username:
                print(f"Username from token: {username}")

            # Show token expiration
            try:
                parts = token.split('.')
                payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                decoded = json.loads(base64.b64decode(payload))
                exp = decoded.get('exp')
                if exp:
                    exp_date = datetime.fromtimestamp(exp)
                    print(f"Token expires: {exp_date}")
            except:
                pass

        except Exception as e:
            print(f"Failed to get token: {e}")
        return

    # Get JWT token via configured authentication method
    try:
        print("Authenticating with Azure AD...")
        token = auth_manager.get_jwt_token(force_refresh=args.force_refresh)
        print("Authentication successful!")

        # Launch cqlsh with token
        launch_cqlsh_with_token(cqlsh_args, token, args.username)

    except Exception as e:
        print(f"Authentication failed: {e}")
        print("\nTroubleshooting tips:")
        print("1. Run --setup to configure authentication")
        print("2. Run --clear-cache to clear cached tokens")
        print("3. Check ~/.cassandra/cqlsh_token.log for detailed errors")
        print("4. Verify your Azure AD app registration configuration")
        sys.exit(1)

if __name__ == '__main__':
    main()