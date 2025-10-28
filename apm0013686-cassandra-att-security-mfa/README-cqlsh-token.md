Cassandra JWTAuthenticator Integration Guide
This guide shows how to set up the cqlsh-token script to work with your Cassandra cluster that has JWTAuthenticator and JWTAuthorizer configured.
Prerequisites
1. Install Python Dependencies
   bashpip install azure-identity requests configparser
2. Azure AD Application Registration
   You need an Azure AD application registration configured for your Cassandra authentication:

Go to Azure Portal > Azure Active Directory > App registrations
Create a new registration or use existing one
Configure redirect URI: http://localhost:8080/callback
Note down:

Application (client) ID
Directory (tenant) ID



3. Cassandra JWTAuthenticator Configuration
   Ensure your cassandra.yaml has JWTAuthenticator configured:
   yamlauthenticator: com.github.datastax.cassandra.auth.JWTAuthenticator
   authorizer: com.github.datastax.cassandra.auth.JWTAuthorizer

jwt_authenticator_options:
# Your JWT configuration
secret_key: "your-jwt-secret"
algorithm: "HS256"  # or RS256 if using public/private keys
issuer: "https://sts.windows.net/your-tenant-id/"  # Azure AD issuer
audience: "your-application-id"
username_claim: "preferred_username"  # or "upn", "email"
Installation
1. Install the Script
   bash# Make the script executable
   chmod +x cqlsh-token

# Copy to a directory in your PATH
sudo cp cqlsh-token /usr/local/bin/

# Or create a symlink
sudo ln -s /path/to/cqlsh-token /usr/local/bin/cqlsh-token
2. Initial Configuration
   Run the setup command:
   bashcqlsh-token --setup
   This will prompt for:

Azure AD Application (Client) ID
Azure AD Tenant ID
Token Scope (usually openid profile email)
Cassandra host and port
JWT configuration options

Usage Examples
Basic Usage - Browser Login
bash# Opens browser for Azure login, then connects to Cassandra
cqlsh-token

# Connect to specific host
cqlsh-token your-cassandra-host.com 9042

# Connect with SSL
cqlsh-token --ssl your-cassandra-host.com 9142
Advanced Usage
bash# Show current JWT token
cqlsh-token --show-token

# Clear cached tokens (force new login)
cqlsh-token --clear-cache

# Use custom config file
cqlsh-token --config ~/my-jwt-config

# Override username but use token as password
cqlsh-token --username myuser your-host.com

# Pass through cqlsh options
cqlsh-token -k mykeyspace --ssl your-host.com
Configuration File
The configuration is stored in ~/.cassandra/jwt_config:
ini[azure]
client_id = your-azure-client-id
tenant_id = your-azure-tenant-id
scope = openid profile email
redirect_uri = http://localhost:8080/callback
authority = https://login.microsoftonline.com/

[cassandra]
host = your-cassandra-host.com
port = 9042
ssl = true
username =
keyspace =

[jwt]
use_token_as_username = false
username_claim = preferred_username
token_format = raw
Configuration Options Explained
Azure Section

client_id: Your Azure AD application client ID
tenant_id: Your Azure AD tenant ID (or 'common' for multi-tenant)
scope: OAuth scopes to request (determines what's in the JWT)
redirect_uri: Where Azure redirects after login (must match app registration)

Cassandra Section

host/port: Default Cassandra connection details
ssl: Whether to use SSL by default
username: Static username (if not using token-based username)
keyspace: Default keyspace to connect to

JWT Section

use_token_as_username: If true, use entire JWT token as username
username_claim: Which JWT claim contains the username (if not using token as username)
token_format: Whether to prefix token with "Bearer " or use raw token

Authentication Flow

Browser Opens: Script opens browser to Azure AD login page
User Authenticates: User enters credentials in browser
Token Received: Azure AD returns JWT token to script
Token Cached: Token is cached locally for reuse
cqlsh Launched: Script launches cqlsh with JWT token as credentials

Troubleshooting
Common Issues
"cqlsh not found in PATH"
bash# Add Cassandra bin to PATH
export PATH=$PATH:/path/to/cassandra/bin

# Or specify full path to cqlsh in the script
"Azure authentication failed"

Check your Azure AD app registration configuration
Ensure redirect URI matches exactly
Verify tenant ID and client ID are correct

"Browser doesn't open"
The script will fall back to device code flow:

Copy the device code shown
Open https://microsoft.com/devicelogin
Enter the device code
Complete authentication

"JWT token rejected by Cassandra"
Check your Cassandra JWTAuthenticator configuration:

Verify issuer matches Azure AD (https://sts.windows.net/tenant-id/)
Check audience matches your application ID
Ensure username_claim exists in the JWT token

Debug Information
Check the log file for detailed information:
bashtail -f ~/.cassandra/cqlsh_token.log
Enable debug logging by setting log level in config:
ini[logging]
level = DEBUG
Token Inspection
To see what's in your JWT token:
bash# Show token summary
cqlsh-token --show-token

# Decode token manually (for debugging)
python3 -c "
import base64, json, sys
token = 'your-jwt-token'
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
print(json.dumps(json.loads(base64.b64decode(payload)), indent=2))
"
Integration with Scripts
Shell Script Example
bash#!/bin/bash
# Automated CQL script execution with JWT auth

# Clear any cached tokens for fresh login
cqlsh-token --clear-cache

# Execute CQL commands
cqlsh-token your-cassandra-host.com << EOF
USE mykeyspace;
CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, name TEXT);
INSERT INTO users (id, name) VALUES (uuid(), 'Test User');
SELECT * FROM users;
EOF
Python Script Example
pythonimport subprocess
import os

def run_cql_with_jwt(cql_commands, host='localhost'):
"""Run CQL commands using JWT authentication"""

    # Build command
    cmd = ['cqlsh-token', host]
    
    # Execute with CQL input
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = process.communicate(input=cql_commands)
    
    if process.returncode != 0:
        raise Exception(f"CQL execution failed: {stderr}")
    
    return stdout

# Usage
cql = """
USE system;
SELECT cluster_name FROM local;
"""

result = run_cql_with_jwt(cql, 'your-cassandra-host.com')
print(result)
Security Considerations
Token Storage

Tokens are cached in ~/.cassandra/jwt_token_cache with 600 permissions
Tokens automatically refresh when expired
Clear cache regularly in shared environments

Network Security

Always use SSL for production Cassandra connections
The redirect URI uses localhost:8080 - ensure this port is available

Azure AD Configuration

Use least-privilege principle for token scopes
Consider using managed identities for production deployments
Regularly rotate client secrets if using service principal authentication

Production Deployment
Using Managed Identity (Recommended)
For production deployments on Azure VMs:
ini[azure]
# Use managed identity instead of interactive login
authentication_method = managed_identity
client_id = your-managed-identity-client-id
scope = your-custom-scope/.default
Then modify the script to use ManagedIdentityCredential instead of InteractiveBrowserCredential.
Service Principal Authentication
For automation scenarios:
ini[azure]
authentication_method = service_principal
client_id = your-service-principal-client-id
client_secret = your-service-principal-secret
tenant_id = your-tenant-id
Custom Token Validation
If your Cassandra cluster validates tokens against a custom endpoint, modify the AzureJWTAuthManager