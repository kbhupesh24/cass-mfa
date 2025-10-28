# LDAP & JWT Security Provider for Apache Cassandra

A unified plugin enabling LDAP and/or JWT authentication and authorization for Cassandra, supporting hybrid and chained authentication/authorization strategies.

---

## 🚀 User Guide: Deploying the Shaded JAR

### 1. Download & Install
- Download the latest shaded JAR from the [Releases page](https://github.com/att/ldap-security-provider/releases).
- Copy it to your Cassandra lib directory:
  ```bash
  cp ldap-security-provider-<version>.jar $CASSANDRA_HOME/lib/
  ```

### 2. Cassandra Settings
- In `cassandra.yaml`:
  ```yaml
  authenticator: com.att.cassandra.security.auth.ChainedAuthenticator
  authorizer:    com.att.cassandra.security.auth.ChainedAuthorizer
  ```

### 3. Create `security.yaml`
Place this in `$CASSANDRA_HOME/conf/security.yaml` (or on the classpath).

#### **A. LDAP with Active Directory Example**
```yaml
cache:
  ttlSeconds: 60
  cleanupAfterSeconds: 300
roles:
  clusters:
    prod-cluster:
      my_keyspace: MYKS_PROD
    dev-cluster:
      my_keyspace: MYKS_DEV
    test-cluster:
      my_keyspace: MYKS_TEST
internal_users:
  - cassandra
authenticators:
  ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthenticator
    url: ldap://ad.example.com:389
    bindUser: cn=admin,dc=example,dc=org
    bindPassword: secret
    userBaseDn: "ou=users,dc=example,dc=org"
    userAttribute: uid
    groupBaseDn: "ou=groups,dc=example,dc=org"
    groupAttribute: cn
    groupObjectClass: groupOfNames
    groupMemberAttribute: member
  internal:
    class: org.apache.cassandra.auth.PasswordAuthenticator
  # ...add more as needed...
authorizers:
  ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthorizer
  cassandra:
    class: org.apache.cassandra.auth.CassandraAuthorizer
chained:
  authenticators: [ldap, internal]
  authorizers: [ldap, cassandra]
```

#### **B. Azure Entra (OAuth/JWT) Example**
```yaml
authenticators:
  jwt:
    class: com.att.cassandra.security.auth.jwt.JwtAuthenticator
    jwksUrl: https://login.microsoftonline.com/common/discovery/keys
    issuer: https://sts.windows.net/<tenant-id>/
    audience: <your-app-client-id>
  internal:
    class: org.apache.cassandra.auth.PasswordAuthenticator
authorizers:
  jwt:
    class: com.att.cassandra.security.auth.jwt.JwtAuthorizer
  cassandra:
    class: org.apache.cassandra.auth.CassandraAuthorizer
chained:
  authenticators: [jwt, internal]
  authorizers: [jwt, cassandra]
```

#### **C. Hybrid/Chained Example (LDAP + JWT + Internal)**
```yaml
cache:
  ttlSeconds: 60
  cleanupAfterSeconds: 300
internal_users:
  - cassandra
authenticators:
  ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthenticator
    url: ldap://ad.example.com:389
    bindUser: cn=admin,dc=example,dc=org
    bindPassword: secret
    userBaseDn: "ou=users,dc=example,dc=org"
    userAttribute: uid
    groupBaseDn: "ou=groups,dc=example,dc=org"
    groupAttribute: cn
    groupObjectClass: groupOfNames
    groupMemberAttribute: member
  jwt:
    class: com.att.cassandra.security.auth.jwt.JwtAuthenticator
    jwksUrl: https://login.microsoftonline.com/common/discovery/keys
    issuer: https://sts.windows.net/<tenant-id>/
    audience: <your-app-client-id>
  internal:
    class: org.apache.cassandra.auth.PasswordAuthenticator
authorizers:
  ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthorizer
  jwt:
    class: com.att.cassandra.security.auth.jwt.JwtAuthorizer
  cassandra:
    class: org.apache.cassandra.auth.CassandraAuthorizer
chained:
  authenticators: [ldap, jwt, internal]
  authorizers: [ldap, jwt, cassandra]
```

#### **D. Multi-Provider Chain Example**
```yaml
authenticators:
  corp_ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthenticator
    # ...corp LDAP config...
  partner_ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthenticator
    # ...partner LDAP config...
  jwt_internal:
    class: com.att.cassandra.security.auth.jwt.JwtAuthenticator
    # ...internal JWT config...
  jwt_external:
    class: com.att.cassandra.security.auth.jwt.JwtAuthenticator
    # ...external JWT config...
  internal:
    class: org.apache.cassandra.auth.PasswordAuthenticator
authorizers:
  ldap:
    class: com.att.cassandra.security.auth.ldap.LdapAuthorizer
  jwt:
    class: com.att.cassandra.security.auth.jwt.JwtAuthorizer
  cassandra:
    class: org.apache.cassandra.auth.CassandraAuthorizer
chained:
  authenticators: [corp_ldap, partner_ldap, jwt_internal, jwt_external, internal]
  authorizers: [ldap, jwt, cassandra]
```

---

## 🔒 How Chained Authentication & Authorization Works

- The order in `chained.authenticators` determines which authentication provider is tried first.
- Each logical name in the chain (e.g., `ldap`, `jwt`, `internal`) must have a corresponding config block under `authenticators`.
- The same applies for `authorizers`.
- You can define multiple logical providers of the same type (e.g., multiple LDAPs or JWTs) and reference them in the chain.
- When a client connects, the chain is tried in order until one authenticator succeeds. The same applies for authorization.

### Cluster-Aware Roles Mapping
- The security provider now scopes roles-to-keyspace mapping by Cassandra cluster name (from `DatabaseDescriptor.getClusterName()`).
- In your `security.yaml`, use:
  ```yaml
  roles:
    clusters:
      <cluster_name>:
        my_keyspace: MYKS_<CLUSTER>
  ```
- This ensures the same keyspace name in different clusters maps to different group prefixes and avoids cross-cluster permission leakage.
- No need to set `CASS_ENV` or use an environment property.

## Group/Role Mapping Format (LDAP & JWT)

- Permissions are mapped using group/role strings in the format:
  `<CLUSTER>-<RESOURCE>-<KEYSPACE>-<OBJECT>-<ACTION>`
- Example: `my-cluster-data-ks1-users-SELECT`
- **CLUSTER:** Cassandra cluster name (spaces replaced with underscores in group/role name)
- **RESOURCE:** data, roles, functions, types, mbeans, etc.
- **KEYSPACE:** keyspace name or `*`
- **OBJECT:** table/function/type name or `*`
- **ACTION:** Cassandra permission (e.g., SELECT, MODIFY, AUTHORIZE) or `*`
- Wildcards (`*`) are supported in any position.
- This format is used for both LDAP group names and JWT role/group claims for consistent, cluster-aware authorization.

---

## 🛠️ Developer Guide

### Local Integration Testing
- See `README-local-config-pattern.md` and `local-config/README-local-config.md` for how to set up local integration test configs.
- Copy `.example` files from `local-config/` and edit for your environment.
- Never check secrets into git.
- Integration tests will use configs from `local-config/` if present.

### Build & Test
```bash
mvn clean package
mvn test
```

### Example: azure-entra-client.json
```json
{
  "client_id": "YOUR-CLIENT-ID",
  "client_secret": "YOUR-CLIENT-SECRET",
  "tenant_id": "YOUR-TENANT-ID",
  "authority": "https://login.microsoftonline.com/YOUR-TENANT-ID",
  "scope": "api://YOUR-API-ID/.default"
}
```

### Example: cassandra-test.yaml
```yaml
cluster_name: 'Test Cluster'
num_tokens: 1
data_file_directories:
    - /tmp/cassandra/data
commitlog_directory: /tmp/cassandra/commitlog
saved_caches_directory: /tmp/cassandra/saved_caches
hints_directory: /tmp/cassandra/hints
partitioner: org.apache.cassandra.dht.Murmur3Partitioner
listen_address: 127.0.0.1
rpc_address: 127.0.0.1
endpoint_snitch: SimpleSnitch
authenticator: com.att.cassandra.security.auth.ChainedAuthenticator
authorizer: com.att.cassandra.security.auth.ChainedAuthorizer
native_transport_port: 9142
commitlog_sync: periodic
commitlog_sync_period: 10000ms
seed_provider:
    - class_name: org.apache.cassandra.locator.SimpleSeedProvider
      parameters:
          - seeds: "127.0.0.1"
```

---

## 🧩 Troubleshooting & Best Practices
- Ensure all logical names in the `chained` section have a matching config block.
- For hybrid environments, always include `password` or `cassandra` as a fallback for admin/internal users.
- Use the provided `.example` files in `local-config/` as templates for your own secure configs.
- For Azure Entra, ensure your JWT config matches your Azure app registration and tenant settings.
- For LDAP, verify connectivity and credentials with an external LDAP client if you encounter issues.

---

## 📝 License
Copyright 2025 AT&T Intellectual Properties, Inc.

---

## Error/Warning/Info Code Reference

| Code   | Type  | Description                                                      | Typical Cause / Context                                   | Recommended User Action                |
|--------|-------|------------------------------------------------------------------|-----------------------------------------------------------|----------------------------------------|
| E102   | Error | security.yaml not found                                          | Missing configuration file                                | Ensure security.yaml is present        |
| E103   | Error | Failed to load configuration / LdapService not initialized       | Malformed YAML, missing fields, or service init failure   | Check YAML syntax and required fields  |
| E104   | Error | Groups can only be set once                                      | Attempt to set groups multiple times for a user           | Review group assignment logic          |
| E106   | Error | No authnId / Username or password not provided                   | Missing username or password in login                     | Provide both username and password     |
| E107   | Error | SASL not complete                                                | SASL negotiation incomplete                               | Check SASL client/server configuration |
| E108   | Error | Config validation errors (authenticators/authorizers/roles)      | Invalid or missing config sections                        | Review and correct security.yaml       |
| E109   | Error | Unknown authorization mode                                       | Unsupported mode in config                                | Use a supported mode                   |
| E110   | Error | Unsupported operation in authorizer                              | Attempt to grant/revoke/list permissions locally          | Use LDAP/JWT for permission management |
| E111   | Error | LoginException (JWT/LDAP) / LDAP bind failed                     | LDAP/JWT login failure                                   | Check credentials, LDAP/JWT server     |
| W201   | Warn  | User has no groups in LDAP                                       | User not a member of any LDAP group                       | Add user to appropriate LDAP groups    |
| W202   | Warn  | Failed to fetch groups for user                                  | LDAP query failure, network issue, or misconfig           | Check LDAP connectivity and config     |
| W203   | Warn  | UserInfo endpoint returned non-200                               | JWT UserInfo endpoint error                               | Check endpoint and network             |
| W204   | Warn  | Error calling UserInfo endpoint                                  | Exception during UserInfo call                            | Check endpoint, network, and logs      |

---

## How to extend
- When adding a new error/warn/info code, update `ErrorCodes.java` and this table.
- Use codes in all log messages and thrown exceptions for traceability.
- Document the context and recommended action for each code.
