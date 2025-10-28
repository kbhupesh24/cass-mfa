# Local Developer Configs for Integration Testing

This directory is **not checked into git**. Place your real, developer-specific, or secret configuration files here for integration testing.

## What to put here
- `cassandra-test.yaml` — Example config for integration tests. Use ChainedAuthenticator/ChainedAuthorizer and set JVM properties for chaining.
- `security.yaml` — Example config for hybrid/chained authentication/authorization modes.
- `ldap-security.yaml` — (Optional) LDAP-specific config
- `azure-entra-client.json` — (Optional) Azure Entra client config for test users
- `test-users.env` — (Optional) Test user credentials for client-side tests

## How to use
1. Copy the example files from `src/test/resources/` to this folder and edit them for your environment.
2. **Never check secrets or real credentials into git!**
3. The integration test will automatically use files from here if present.
