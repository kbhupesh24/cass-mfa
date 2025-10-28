package com.att.cassandra.security.config;

import com.att.cassandra.security.ErrorCodes;

import java.util.List;
import java.util.Map;

/**
 * Top-level configuration for authentication and authorization.
 * Contains sections for LDAP, caching, role mappings, and JWT settings.
 */
public class SecurityConfig {
    private CacheConfig cache;
    private ChainedConfig chained;
    private Map<String, Object> authenticators;
    private Map<String, Object> authorizers;
    private Map<String, Object> externalServices;
    private List<String> internalUsers;
    private boolean userAutoAdd = false;

    // Remove old RolesConfig and add new keyspaces and defaultRoles
    private List<KeyspaceRolesConfig> keyspaces;
    private List<RoleConfig> defaultRoles;

    public CacheConfig getCache() { return cache; }
    public void setCache(CacheConfig cache) { this.cache = cache; }

    public ChainedConfig getChained() { return chained; }
    public void setChained(ChainedConfig chained) { this.chained = chained; }

    public Map<String, Object> getAuthenticators() { return authenticators; }
    public void setAuthenticators(Map<String, Object> authenticators) { this.authenticators = authenticators; }
    public Map<String, Object> getAuthorizers() { return authorizers; }
    public void setAuthorizers(Map<String, Object> authorizers) { this.authorizers = authorizers; }
    public Map<String, Object> getExternalServices() { return externalServices; }
    public void setExternalServices(Map<String, Object> externalServices) { this.externalServices = externalServices; }
    public List<String> getInternalUsers() { return internalUsers; }
    public void setInternalUsers(List<String> internalUsers) { this.internalUsers = internalUsers; }
    public boolean isUserAutoAdd() { return userAutoAdd; }
    public void setUserAutoAdd(boolean userAutoAdd) { this.userAutoAdd = userAutoAdd; }

    public List<KeyspaceRolesConfig> getKeyspaces() { return keyspaces; }
    public void setKeyspaces(List<KeyspaceRolesConfig> keyspaces) { this.keyspaces = keyspaces; }

    public List<RoleConfig> getDefaultRoles() { return defaultRoles; }
    public void setDefaultRoles(List<RoleConfig> defaultRoles) { this.defaultRoles = defaultRoles; }

    /**
     * Validate that mode flags correspond to provided auth/authorization configs.
     */
    public void validate() {
        if (authenticators == null || authenticators.isEmpty())
            throw new RuntimeException(ErrorCodes.E108 + ": at least one authenticator must be configured");
        if (authorizers == null || authorizers.isEmpty())
            throw new RuntimeException(ErrorCodes.E108 + ": at least one authorizer must be configured");
    }

    /**
     * Static helper to fetch an external service config by logical name.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> getExternalServiceConfig(String logicalName) {
        SecurityConfig config = ConfigLoader.load();
        Map<String, Object> externalServices = config.getExternalServices();
        if (externalServices == null || !externalServices.containsKey(logicalName)) {
            throw new IllegalArgumentException("No external_service config found for logical name: " + logicalName);
        }
        Object raw = externalServices.get(logicalName);
        if (!(raw instanceof Map)) {
            throw new IllegalArgumentException("Config for logical name '" + logicalName + "' is not a map");
        }
        return (Map<String, Object>) raw;
    }
}
