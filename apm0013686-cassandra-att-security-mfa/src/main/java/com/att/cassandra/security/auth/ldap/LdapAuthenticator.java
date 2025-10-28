package com.att.cassandra.security.auth.ldap;

import com.att.cassandra.security.auth.ChainedAuthenticator.SupportsCredentialType;
import org.apache.cassandra.auth.*;
import org.apache.cassandra.exceptions.AuthenticationException;
import java.net.InetAddress;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.att.cassandra.security.config.SecurityConfig;

public class LdapAuthenticator implements IAuthenticator, SupportsCredentialType {
    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticator.class);
    private LdapService ldapService;
    private String logicalName;

    public LdapAuthenticator(String logicalName) { this.logicalName = logicalName; }
    public void setLogicalName(String logicalName) {
        this.logicalName = logicalName;
        if (ldapService == null) setup(); // Ensure service is initialized
    }

    @Override
    public void validateConfiguration() {}

    @Override
    public void setup() {
        logger.info("[LdapAuthenticator] setup() called for logicalName: {}", logicalName);
        ldapService = LdapService.getInstance(logicalName);
    }

    @Override
    public boolean requireAuthentication() { return true; }

    @Override
    public Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() {
        return Collections.emptySet();
    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress) {
        if (ldapService == null) setup();
        return new LdapSaslNegotiator();
    }

    private void autoAddUserIfNeeded(String username) {
        if (username == null || username.isEmpty()) {
            logger.warn("[LdapAuthenticator] autoAddUserIfNeeded called with null/empty username");
            return;
        }
        SecurityConfig config = com.att.cassandra.security.config.ConfigLoader.load();
        if (config.isUserAutoAdd()) {
            logger.debug("[LdapAuthenticator] userAutoAdd is enabled, checking if user '{}' exists in system_auth.roles", username);
            try {
                String checkRoleCql = String.format("SELECT role FROM system_auth.roles WHERE role='%s'", username.replace("'", "''"));
                logger.debug("[LdapAuthenticator] Executing CQL to check role existence: {}", checkRoleCql);
                org.apache.cassandra.cql3.UntypedResultSet rows = org.apache.cassandra.cql3.QueryProcessor.process(
                    checkRoleCql, org.apache.cassandra.db.ConsistencyLevel.LOCAL_ONE);
                if (rows.isEmpty()) {
                    logger.debug("[LdapAuthenticator] User '{}' does not exist in system_auth.roles, fetching LDAP groups", username);
                    java.util.Set<String> groups = ldapService.fetchUserGroups(username);
                    logger.debug("[LdapAuthenticator] LDAP groups for '{}': {}", username, groups);
                    if (groups != null && !groups.isEmpty()) {
                        logger.info("[LdapAuthenticator] Auto-adding user {} to system_auth.roles (userAutoAdd enabled)", username);
                        String createRoleCql = String.format(
                            "CREATE ROLE IF NOT EXISTS \"%s\" WITH LOGIN = true AND SUPERUSER = false",
                            username.replace("\"", "\"\""));
                        logger.debug("[LdapAuthenticator] Executing CQL to create role: {}", createRoleCql);
                        // Use a superuser ClientState and QueryState for CREATE ROLE
                        org.apache.cassandra.service.ClientState state = org.apache.cassandra.service.ClientState.forInternalCalls();
                        state.login(new org.apache.cassandra.auth.AuthenticatedUser("cassandra")); // or your superuser name
                        org.apache.cassandra.service.QueryState qstate = new org.apache.cassandra.service.QueryState(state);
                        org.apache.cassandra.cql3.QueryProcessor.process(
                            createRoleCql,
                            org.apache.cassandra.db.ConsistencyLevel.LOCAL_ONE,
                            qstate,
                            null); // null for request time is safe for internal synchronous queries
                    } else {
                        logger.warn("[LdapAuthenticator] userAutoAdd enabled but user {} has no groups/roles, not auto-adding", username);
                    }
                } else {
                    logger.debug("[LdapAuthenticator] User '{}' already exists in system_auth.roles, skipping auto-add", username);
                }
            } catch (Exception e) {
                logger.error("[LdapAuthenticator] Failed to auto-add user {}: {}", username, e.getMessage(), e);
            }
        }
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        if (ldapService == null) setup();
        String username = credentials.get("username");
        String password = credentials.get("password");
        logger.info("[LdapAuthenticator] legacyAuthenticate called for user: {}", username);
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            logger.warn("[LdapAuthenticator] Missing username or password");
            throw new AuthenticationException("Missing username or password");
        }
        if (password != null && password.startsWith("Bearer ")) {
            logger.warn("[LdapAuthenticator] Bearer token not supported for user: {}", username);
            throw new AuthenticationException("LDAP authenticator does not support Bearer tokens");
        }
        if (!ldapService.authenticateBind(username, password)) {
            logger.warn("[LdapAuthenticator] LDAP authentication failed for user: {}", username);
            throw new AuthenticationException("LDAP authentication failed for user: " + username);
        }
        logger.info("[LdapAuthenticator] LDAP authentication succeeded for user: {}", username);
        // Auto-add user to system_auth.roles if enabled and user has any groups/roles
        autoAddUserIfNeeded(username);
        return new AuthenticatedUser(username);
    }

    @Override
    public boolean supports(byte[] initialSaslPayload) {
        // SASL PLAIN: 0x00 user 0x00 pass
        int firstNull = -1, secondNull = -1;
        for (int i = 0, nulls = 0; i < initialSaslPayload.length; i++) {
            if (initialSaslPayload[i] == 0) {
                if (nulls == 0) firstNull = i;
                else if (nulls == 1) secondNull = i;
                nulls++;
            }
        }
        if (firstNull >= 0 && secondNull >= 0 && secondNull + 1 < initialSaslPayload.length) {
            String password = new String(initialSaslPayload, secondNull + 1, initialSaslPayload.length - (secondNull + 1));
            return !password.startsWith("Bearer ");
        }
        return true; // fallback: if not a Bearer token, assume LDAP/Password
    }

    class LdapSaslNegotiator implements SaslNegotiator {
        private boolean complete = false;
        private String username;
        private String password;

        @Override
        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
            // SASL PLAIN: 0x00 user 0x00 pass
            int firstNull = -1, secondNull = -1;
            for (int i = 0, nulls = 0; i < clientResponse.length; i++) {
                if (clientResponse[i] == 0) {
                    if (nulls == 0) firstNull = i;
                    else if (nulls == 1) secondNull = i;
                    nulls++;
                }
            }
            if (firstNull >= 0 && secondNull >= 0 && secondNull + 1 < clientResponse.length) {
                username = new String(clientResponse, firstNull + 1, secondNull - (firstNull + 1));
                password = new String(clientResponse, secondNull + 1, clientResponse.length - (secondNull + 1));
                logger.info("[LdapAuthenticator] SASL authenticate for user: {}", username);
                if (password.startsWith("Bearer ")) {
                    logger.warn("[LdapAuthenticator] Bearer token not supported for user: {}", username);
                    throw new AuthenticationException("LDAP authenticator does not support Bearer tokens");
                }
                if (!ldapService.authenticateBind(username, password)) {
                    logger.warn("[LdapAuthenticator] LDAP authentication failed for user: {}", username);
                    throw new AuthenticationException("LDAP authentication failed for user: " + username);
                }
                logger.info("[LdapAuthenticator] LDAP authentication succeeded for user: {}", username);
                // Auto-add user to system_auth.roles if enabled and user has any groups/roles
                autoAddUserIfNeeded(username);
                complete = true;
                return null;
            }
            throw new AuthenticationException("Malformed SASL payload for LDAP");
        }

        @Override
        public boolean isComplete() { return complete; }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
            if (!complete) throw new AuthenticationException("SASL not complete");
            return new AuthenticatedUser(username);
        }
    }

    // For test injection
    void setLdapServiceForTest(LdapService svc) { this.ldapService = svc; }
}
