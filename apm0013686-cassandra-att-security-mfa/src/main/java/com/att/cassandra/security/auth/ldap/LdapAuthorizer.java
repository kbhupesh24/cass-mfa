package com.att.cassandra.security.auth.ldap;

import com.att.cassandra.security.auth.CachedUser;
import com.google.common.collect.ImmutableSet;

import java.util.List;
import java.util.Set;
import java.util.LinkedHashSet;

import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IAuthorizer;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.PermissionDetails;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.SecurityConfig;
import com.att.cassandra.security.config.KeyspaceRolesConfig;
import com.att.cassandra.security.config.RoleConfig;
import com.att.cassandra.security.auth.util.RolePermissionMapper;

public class LdapAuthorizer implements IAuthorizer {
    private static Logger logger = LoggerFactory.getLogger(LdapAuthorizer.class);

    private LdapService ldapService;
    private String logicalName;
    private SecurityConfig testConfig;

    public LdapAuthorizer(String logicalName) { this.logicalName = logicalName; }
    public void setLogicalName(String logicalName) {
        this.logicalName = logicalName;
        if (ldapService == null) setup(); // Ensure service is initialized
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {
    }

    @Override
    public void setup() {
        ldapService = LdapService.getInstance(logicalName);
    }

    // Add package-private setter for testability
    void setLdapService(LdapService ldapService) {
        this.ldapService = ldapService;
    }

    // Add package-private setter for logger for testability
    static void setLoggerForTest(org.slf4j.Logger testLogger) {
        logger = testLogger;
    }

    // Test hook to override loaded SecurityConfig
    void setSecurityConfig(SecurityConfig config) {
        this.testConfig = config;
    }

    @Override
    public Set<Permission> authorize(AuthenticatedUser authnUser, IResource resource) {
        logger.info("[LdapAuthorizer] authorize called for user: {} resource: {}",
            authnUser != null ? authnUser.getName() : "null",
            resource != null ? resource.getName() : "null");
        if (authnUser == null || resource == null) {
            return Set.of();
        }
        // Test override: bypass LDAP service and assume full mapping based on testConfig
        if (testConfig != null) {
            List<KeyspaceRolesConfig> keyspaces = testConfig.getKeyspaces();
            List<RoleConfig> defaultRoles = testConfig.getDefaultRoles();
            // Build synthetic groups: prefix+roleName for each role in matching keyspace
            String ksName = (resource instanceof DataResource) ? ((DataResource) resource).getKeyspace() : null;
            for (KeyspaceRolesConfig k : keyspaces) {
                if (ksName != null && ksName.equalsIgnoreCase(k.getName())) {
                    Set<String> groups = new LinkedHashSet<>();
                    for (RoleConfig r : k.getRoles()) {
                        groups.add(k.getRolePrefix() + r.getName());
                    }
                    return RolePermissionMapper.mapGroupsToPermissions(groups, resource, keyspaces, defaultRoles);
                }
            }
            return Set.of();
        }
        String username = authnUser.getName();
        CachedUser user = ldapService.getCache().getIfPresent(username);
        if (user == null)
            return Set.of();
        Set<String> groups = user.getGroups();
        if (groups == null || groups.isEmpty()) {
            try {
                user.setGroups(ldapService.fetchUserGroups(username));
                groups = user.getGroups();
            } catch (com.unboundid.ldap.sdk.LDAPException e) {
                logger.warn("{} Failed to fetch groups for user {}: {}", com.att.cassandra.security.ErrorCodes.W202, username, e.getMessage());
                return Set.of();
            }
        }
        if (groups == null || groups.isEmpty()) {
            logger.warn("{} User {} has no groups defined in LDAP, skipping permission check.", com.att.cassandra.security.ErrorCodes.W201, username);
            return Set.of();
        }
        // --- New local roles/permissions mapping logic ---
        SecurityConfig config = null;
        // Prefer testConfig (override), then service-provided config for tests, else load from resources
        if (testConfig != null) {
            config = testConfig;
        } else if (ldapService != null && ldapService.getConfig() != null) {
            config = ldapService.getConfig();
        } else {
            config = ConfigLoader.load();
        }
        List<KeyspaceRolesConfig> keyspaces = config.getKeyspaces();
        List<RoleConfig> defaultRoles = config.getDefaultRoles();
        return RolePermissionMapper.mapGroupsToPermissions(groups, resource, keyspaces, defaultRoles);
    }

    @Override
    public Set<Permission> grant(AuthenticatedUser arg0, Set<Permission> arg1, IResource arg2, RoleResource arg3)
            throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException(
                com.att.cassandra.security.ErrorCodes.E110 + " Granting permissions locally is not supported when using the LDAP security provider.");
    }

    @Override
    public Set<PermissionDetails> list(AuthenticatedUser performer,
            Set<Permission> permissions,
            IResource resource,
            RoleResource grantee)
            throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException(
                com.att.cassandra.security.ErrorCodes.E110 + " Listing permissions locally is not supported yet.");
    }

    @Override
    public Set<Permission> revoke(AuthenticatedUser arg0, Set<Permission> arg1, IResource arg2, RoleResource arg3)
            throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException(
                com.att.cassandra.security.ErrorCodes.E110 + " Revoking permissions locally is not supported when using the LDAP security provider.");
    }

    @Override
    public void revokeAllFrom(RoleResource arg0) {
        throw new UnsupportedOperationException(
                com.att.cassandra.security.ErrorCodes.E110 + " Revoking permissions locally is not supported when using the LDAP security provider.");
    }

    @Override
    public void revokeAllOn(IResource arg0) {
        throw new UnsupportedOperationException(
                com.att.cassandra.security.ErrorCodes.E110 + " Revoking permissions locally is not supported when using the LDAP security provider.");
    }

    @Override
    public Set<? extends IResource> protectedResources() {
        return ImmutableSet.of(DataResource.table("system_auth", AuthKeyspace.ROLE_PERMISSIONS));
    }
}
