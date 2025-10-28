# Integration Test Local Config Pattern

This project supports developer-specific, real configuration for integration testing without risking secrets in git.

## How to use

1. **Copy example files** from `local-config/*.example` to `local-config/` (remove `.example` extension).
2. **Edit the files** for your LDAP, Azure Entra, or other environment. Do NOT check in secrets!
3. The integration test will automatically use files from `local-config/` if present.
4. If a file is missing, the test will fail with a clear message.

## Files to provide
- `cassandra-test.yaml` — Cassandra config for integration test
- `security.yaml` — Security provider config (LDAP, Azure Entra, etc)
- `ldap-security.yaml` — (Optional) LDAP-specific config
- `azure-entra-client.json` — (Optional) Azure Entra client config for test users
- `test-users.env` — (Optional) Test user credentials for client-side tests

## Example .gitignore
```
/local-config/
*.env
*.json
*.yaml
*.conf
```

## Example usage in test
```java
Path cassandraYaml = resolveConfig("cassandra-test.yaml");
Path securityYaml = resolveConfig("security.yaml");
// ...
```

## See also
- `local-config/README-local-config.md` for more details and file format examples.
