#!/bin/bash

# cqlsh-token.py Usage Examples
# Demonstrates various ways to use the browser-based Azure authentication wrapper

echo "cqlsh-token Usage Examples"
echo "=========================="
echo

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_example() {
    echo -e "${GREEN}Example:${NC} $1"
    echo -e "${BLUE}Command:${NC} $2"
    if [ -n "$3" ]; then
        echo -e "${YELLOW}Note:${NC} $3"
    fi
    echo
}

# Basic Examples
echo "=== Basic Usage ==="
print_example \
    "Simple connection with browser login" \
    "cqlsh-token" \
    "Opens browser for Azure login, connects to localhost:9042"

print_example \
    "Connect to specific Cassandra host" \
    "cqlsh-token your-cassandra-host.com 9042" \
    "Browser login, then connect to specified host"

print_example \
    "Connect with SSL" \
    "cqlsh-token --ssl your-cassandra-host.com 9142" \
    "Use SSL connection (common for production)"

print_example \
    "Connect to specific keyspace" \
    "cqlsh-token -k mykeyspace your-host.com" \
    "Login and switch to specified keyspace"

# Token Management Examples
echo "=== Token Management ==="
print_example \
    "Show current JWT token" \
    "cqlsh-token --show-token" \
    "Displays cached token info without connecting to Cassandra"

print_example \
    "Clear cached tokens (force new login)" \
    "cqlsh-token --clear-cache" \
    "Forces fresh browser login on next connection"

print_example \
    "Use custom configuration" \
    "cqlsh-token --config ~/my-jwt-config" \
    "Use alternative configuration file"

# Configuration Examples
echo "=== Configuration ==="
print_example \
    "Run initial setup" \
    "cqlsh-token --setup" \
    "Interactive configuration wizard"

print_example \
    "Override username" \
    "cqlsh-token --username myuser your-host.com" \
    "Use specific username but JWT token as password"

# Advanced Examples
echo "=== Advanced Usage ==="
print_example \
    "Execute single command" \
    "cqlsh-token your-host.com -e \"SELECT * FROM system.local;\"" \
    "Login and execute single CQL statement"

print_example \
    "Execute CQL file" \
    "cqlsh-token your-host.com -f script.cql" \
    "Login and execute CQL commands from file"

print_example \
    "Pipe CQL commands" \
    "echo \"USE system; DESCRIBE KEYSPACES;\" | cqlsh-token your-host.com" \
    "Login and execute piped CQL commands"

# Scripting Examples
echo "=== Scripting Examples ==="

cat << 'EOF'
Example 1: Simple CQL execution script
```bash
#!/bin/bash
# Execute CQL commands with JWT auth

cqlsh-token your-cassandra-host.com << 'CQL'
USE mykeyspace;
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    name TEXT,
    email TEXT,
    created_at TIMESTAMP
);
INSERT INTO users (id, name, email, created_at)
VALUES (uuid(), 'John Doe', 'john@example.com', toTimestamp(now()));
SELECT * FROM users;
CQL
```

Example 2: Automated backup script
```bash
#!/bin/bash
# Automated keyspace backup with JWT auth

KEYSPACE="mykeyspace"
BACKUP_DIR="/backups/$(date +%Y%m%d)"
HOST="your-cassandra-host.com"

mkdir -p "$BACKUP_DIR"

# Get list of tables
TABLES=$(cqlsh-token "$HOST" -e "DESCRIBE TABLES;" | grep -v "^$" | tr -d ' ')

for table in $TABLES; do
    echo "Backing up $KEYSPACE.$table..."
    cqlsh-token "$HOST" -e "COPY $KEYSPACE.$table TO '$BACKUP_DIR/${table}.csv';"
done

echo "Backup completed in $BACKUP_DIR"
```

Example 3: Health check script
```bash
#!/bin/bash
# Cassandra health check with JWT auth

HOST="${1:-localhost}"
TIMEOUT=10

echo "Checking Cassandra health on $HOST..."

# Test connection and basic query
if timeout "$TIMEOUT" cqlsh-token "$HOST" -e "SELECT cluster_name FROM system.local;" >/dev/null 2>&1; then
    echo "✓ Cassandra is healthy"

    # Get cluster info
    CLUSTER_NAME=$(cqlsh-token "$HOST" -e "SELECT cluster_name FROM system.local;" | grep -v "cluster_name" | grep -v "^$" | tr -d ' ')
    NODE_COUNT=$(cqlsh-token "$HOST" -e "SELECT COUNT(*) FROM system.peers;" | grep -oE '[0-9]+')

    echo "  Cluster: $CLUSTER_NAME"
    echo "  Nodes: $((NODE_COUNT + 1))"
    exit 0
else
    echo "✗ Cassandra is not responding"
    exit 1
fi
```

Example 4: Schema migration script
```bash
#!/bin/bash
# Database schema migration with JWT auth

HOST="your-cassandra-host.com"
MIGRATION_DIR="./migrations"
KEYSPACE="mykeyspace"

echo "Running schema migrations..."

# Ensure keyspace exists
cqlsh-token "$HOST" -e "
CREATE KEYSPACE IF NOT EXISTS $KEYSPACE
WITH REPLICATION = {
    'class': 'SimpleStrategy',
    'replication_factor': 3
};"

# Run migrations in order
for migration in "$MIGRATION_DIR"/*.cql; do
    if [ -f "$migration" ]; then
        echo "Applying $(basename "$migration")..."
        cqlsh-token "$HOST" -k "$KEYSPACE" -f "$migration"
    fi
done

echo "Schema migrations completed"
```

Example 5: Data export script
```bash
#!/bin/bash
# Export data with JWT authentication

HOST="your-cassandra-host.com"
KEYSPACE="mykeyspace"
OUTPUT_DIR="./exports/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

echo "Exporting data from $KEYSPACE..."

# Get all tables in keyspace
TABLES=$(cqlsh-token "$HOST" -e "SELECT table_name FROM system_schema.tables WHERE keyspace_name='$KEYSPACE';" | grep -v table_name | grep -v "^$" | tr -d ' ')

for table in $TABLES; do
    echo "Exporting $table..."
    cqlsh-token "$HOST" -e "COPY $KEYSPACE.$table TO '$OUTPUT_DIR/${table}.csv' WITH HEADER=true;"
done

echo "Export completed in $OUTPUT_DIR"
```
EOF

# Configuration Examples
echo
echo "=== Configuration File Examples ==="

cat << 'EOF'
Minimal configuration (~/.cassandra/jwt_config):
```ini
[azure]
client_id = your-azure-client-id
tenant_id = your-azure-tenant-id
scope = openid profile email

[cassandra]
host = your-cassandra-host.com
port = 9042
ssl = true
```

Production configuration:
```ini
[azure]
client_id = 12345678-1234-1234-1234-123456789abc
tenant_id = 87654321-4321-4321-4321-cba987654321
scope = openid profile email
redirect_uri = http://localhost:8080/callback
authority = https://login.microsoftonline.com/

[cassandra]
host = prod-cassandra.yourcompany.com
port = 9142
ssl = true
username =
keyspace = production_data

[jwt]
use_token_as_username = false
username_claim = preferred_username
token_format = raw

[logging]
level = INFO
file = ~/.cassandra/cqlsh_token.log
```

Development configuration:
```ini
[azure]
client_id = dev-client-id
tenant_id = common
scope = openid profile email https://graph.microsoft.com/User.Read

[cassandra]
host = dev-cassandra.internal
port = 9042
ssl = false
keyspace = dev_keyspace

[jwt]
use_token_as_username = true
token_format = bearer
```
EOF

echo
echo "=== Environment Variables ==="
cat << 'EOF'
You can also configure via environment variables:

```bash
# Azure configuration
export AZURE_CLIENT_ID="your-client-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_AUTHORITY="https://login.microsoftonline.com/"

# Cassandra configuration
export CASSANDRA_HOST="your-host.com"
export CASSANDRA_PORT="9042"
export CASSANDRA_SSL="true"

# JWT configuration
export JWT_USERNAME_CLAIM="preferred_username"
export JWT_TOKEN_FORMAT="raw"

# Then run normally
cqlsh-token
```
EOF

echo
echo "=== Troubleshooting Commands ==="
print_example \
    "Test Azure authentication only" \
    "cqlsh-token --show-token" \
    "Verifies Azure login without connecting to Cassandra"

print_example \
    "Debug connection issues" \
    "cqlsh-token --debug your-host.com" \
    "Enable verbose logging for troubleshooting"

print_example \
    "Verify configuration" \
    "cat ~/.cassandra/jwt_config" \
    "Check current configuration settings"

print_example \
    "Check log files" \
    "tail -f ~/.cassandra/cqlsh_token.log" \
    "Monitor authentication and connection logs"

print_example \
    "Reset everything" \
    "rm ~/.cassandra/jwt_* && cqlsh-token --setup" \
    "Clear all cached data and reconfigure"

echo
echo "For more detailed information, run: cqlsh-token --help"