package com.att.cassandra.security.auth.ldap;

import com.att.cassandra.security.auth.CachedUser;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.Permission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.CacheLoader;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LdapAuthorizerTest {
    private LdapAuthorizer authorizer;
    private MockLdapService mockService;
    private CachedUser mockUser;
    private LoadingCache<String, CachedUser> cache;
    private com.att.cassandra.security.config.SecurityConfig secConfig;
    private List<com.att.cassandra.security.config.KeyspaceRolesConfig> keyspaceRolesConfigs;
    private List<com.att.cassandra.security.config.RoleConfig> defaultRoles;

    private static final String TEST_CLUSTER = "test_cluster";
    private static final String TEST_KEYSPACE = "ks1";
    private static final String TEST_ROLE = "READ";
    private static final String TEST_ROLE_PREFIX = "AP-MYKS-";

    private static com.att.cassandra.security.config.KeyspaceRolesConfig makeKeyspaceRolesConfig() {
        com.att.cassandra.security.config.KeyspaceRolesConfig ksConfig = new com.att.cassandra.security.config.KeyspaceRolesConfig();
        ksConfig.setName(TEST_KEYSPACE);
        ksConfig.setRolePrefix(TEST_ROLE_PREFIX);
        com.att.cassandra.security.config.RoleConfig role = new com.att.cassandra.security.config.RoleConfig();
        role.setName(TEST_ROLE);
        com.att.cassandra.security.config.ResourcePermissionConfig rpc = new com.att.cassandra.security.config.ResourcePermissionConfig();
        rpc.setType("data");
        rpc.setName("*");
        rpc.setPermissions(java.util.List.of("SELECT"));
        role.setResources(java.util.List.of(rpc));
        ksConfig.setRoles(java.util.List.of(role));
        return ksConfig;
    }

    @BeforeEach
    void setup() {
        authorizer = new LdapAuthorizer("test");
        cache = CacheBuilder.newBuilder().build(new CacheLoader<String, CachedUser>() {
            @Override
            public CachedUser load(@javax.annotation.Nonnull String key) { return null; }
        });
        mockUser = new CachedUser("alice");
        keyspaceRolesConfigs = java.util.List.of(makeKeyspaceRolesConfig());
        defaultRoles = java.util.List.of();
        secConfig = new com.att.cassandra.security.config.SecurityConfig();
        secConfig.setKeyspaces(keyspaceRolesConfigs);
        secConfig.setDefaultRoles(defaultRoles);
        cache.put("alice", mockUser);
        mockService = new MockLdapService(cache, secConfig);
        authorizer.setLdapService(mockService);
    }

    @Test
    void testAuthorizeWithNoUser() {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            Set<Permission> perms = authorizer.authorize(null, null);
            assertTrue(perms.isEmpty());
        }
    }

    @Test
    void testAuthorizeWithNoGroups() {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            // Use a mock that returns no groups for this test
            com.att.cassandra.security.config.SecurityConfig secConfigLocal = new com.att.cassandra.security.config.SecurityConfig();
            secConfigLocal.setKeyspaces(java.util.List.of(makeKeyspaceRolesConfig()));
            secConfigLocal.setDefaultRoles(java.util.List.of());
            mockService = new MockLdapService(mockService.getCache(), secConfigLocal) {
                @Override public java.util.Set<String> fetchUserGroups(String username) { return java.util.Set.of(); }
            };
            authorizer.setLdapService(mockService);
            mockService.getCache().put("alice", mockUser);
            Set<Permission> perms = authorizer.authorize(new AuthenticatedUser("alice"), org.apache.cassandra.auth.Resources.fromName("data/ks1/TABLE1"));
            assertTrue(perms.isEmpty());
        }
    }

    @Test
    void testAuthorizeWithGroups() {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            // Ensure mockUser has only the intended group (role name) and is in cache
            String group = TEST_ROLE_PREFIX + TEST_ROLE; // e.g., "AP-READ"
            System.out.println("DEBUG: group=" + group + ", keyspace=" + TEST_KEYSPACE + ", rolePrefix=" + TEST_ROLE_PREFIX);
            mockUser.setGroups(Set.of(group));
            cache.put("alice", mockUser);
            Set<Permission> perms = authorizer.authorize(new AuthenticatedUser("alice"), org.apache.cassandra.auth.Resources.fromName("data/ks1/tbl"));
            System.out.println("DEBUG: perms=" + perms);
            assertTrue(perms.contains(Permission.valueOf("SELECT")));
        }
    }

    @Test
    void testGrantThrows() {
        assertThrows(UnsupportedOperationException.class, () ->
            authorizer.grant(null, null, null, null));
    }

    @Test
    void testRevokeThrows() {
        assertThrows(UnsupportedOperationException.class, () ->
            authorizer.revoke(null, null, null, null));
    }

    @Test
    void testListThrows() {
        assertThrows(UnsupportedOperationException.class, () ->
            authorizer.list(null, null, null, null));
    }

    @Test
    void testRevokeAllFromThrows() {
        assertThrows(UnsupportedOperationException.class, () ->
            authorizer.revokeAllFrom(null));
    }

    @Test
    void testRevokeAllOnThrows() {
        assertThrows(UnsupportedOperationException.class, () ->
            authorizer.revokeAllOn(null));
    }

    @Test
    void testAuthorizeReturnsEmptyIfUserNotInCache() {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            mockService.getCache().invalidate("alice");
            Set<Permission> perms = authorizer.authorize(new AuthenticatedUser("alice"), org.apache.cassandra.auth.Resources.fromName("data/ks1/TABLE1"));
            assertTrue(perms.isEmpty());
        }
    }

    @Test
    void testAuthorizeWithUserInCacheButNoGroups() {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            // User in cache but no groups set, should fetch group in new format
            CachedUser user = new CachedUser("bob");
            user.setGroups(null); // Explicitly clear groups
            cache.put("bob", user);
            // Patch mockService to return correct group format
            MockLdapService patchedService = new MockLdapService(cache, secConfig) {
                @Override public java.util.Set<String> fetchUserGroups(String username) {
                    // Return new prefix-based group format
                    return java.util.Set.of(TEST_ROLE_PREFIX + TEST_ROLE);
                }
            };
            authorizer.setLdapService(patchedService);
            Set<Permission> perms = authorizer.authorize(new AuthenticatedUser("bob"), org.apache.cassandra.auth.Resources.fromName("data/ks1/tbl"));
            assertTrue(perms.contains(Permission.valueOf("SELECT")));
        }
    }

    @Test
    void testAuthorizeWithNonTableResource() {
        LdapAuthorizer authz = new LdapAuthorizer("testLogicalName");
        com.att.cassandra.security.config.KeyspaceRolesConfig ksConfig = new com.att.cassandra.security.config.KeyspaceRolesConfig();
        ksConfig.setName("testks");
        ksConfig.setRolePrefix("AP-MYKS-");
        com.att.cassandra.security.config.RoleConfig role = new com.att.cassandra.security.config.RoleConfig();
        role.setName("READ");
        com.att.cassandra.security.config.ResourcePermissionConfig rpc = new com.att.cassandra.security.config.ResourcePermissionConfig();
        rpc.setType("data");
        rpc.setName("*");
        rpc.setPermissions(java.util.List.of("SELECT"));
        role.setResources(java.util.List.of(rpc));
        ksConfig.setRoles(java.util.List.of(role));

        com.att.cassandra.security.config.SecurityConfig mockConfig = mock(com.att.cassandra.security.config.SecurityConfig.class);
        when(mockConfig.getKeyspaces()).thenReturn(java.util.List.of(ksConfig));
        authz.setSecurityConfig(mockConfig);

        AuthenticatedUser user = new AuthenticatedUser("testuser");
        org.apache.cassandra.auth.IResource resource = org.apache.cassandra.auth.DataResource.table("testks", "testtable");

        Set<Permission> permissions = authz.authorize(user, resource);
        assertNotNull(permissions);
        assertTrue(permissions.contains(Permission.SELECT));
    }

    @Test
    void testAuthorizeWithGroupNotMappingToPermission() {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            // Ensure mockUser has only a group that does not map to any permission
            mockUser.setGroups(Set.of(TEST_CLUSTER + "-data-ks1-tbl-UNKNOWN"));
            cache.put("alice", mockUser);
            Set<Permission> perms = authorizer.authorize(new AuthenticatedUser("alice"), org.apache.cassandra.auth.Resources.fromName("data/ks1/tbl"));
            assertTrue(perms.isEmpty());
        }
    }

    @Test
    void testSetLogicalName() {
        com.att.cassandra.security.config.SecurityConfig config = new com.att.cassandra.security.config.SecurityConfig();
        java.util.HashMap<String, Object> externalServices = new java.util.HashMap<>();
        externalServices.put("bar", java.util.Map.of("url", "ldap://localhost", "bindUser", "admin", "bindPassword", "pw", "userDnPattern", "uid={0}", "groupBaseDn", "ou=groups", "groupAttribute", "cn"));
        config.setExternalServices(externalServices);
        // Add minimal cache config
        com.att.cassandra.security.config.CacheConfig cache = new com.att.cassandra.security.config.CacheConfig();
        cache.setTtlSeconds(60);
        cache.setCleanupAfterSeconds(120);
        config.setCache(cache);
        com.att.cassandra.security.auth.ldap.LdapService.setTestConfig(config);
        LdapAuthorizer authz = new LdapAuthorizer("foo");
        authz.setLogicalName("bar");
        // No exception expected
        com.att.cassandra.security.auth.ldap.LdapService.clearTestConfig();
    }

    @Test
    void testValidateConfigurationNoop() throws org.apache.cassandra.exceptions.ConfigurationException {
        authorizer.validateConfiguration(); // Should not throw
    }

    @Test
    void testSetLoggerForTest() {
        org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger("test");
        LdapAuthorizer.setLoggerForTest(logger);
        // No exception expected
    }

    @Test
    void testProtectedResourcesReturnsImmutableSet() {
        Set<?> resources = authorizer.protectedResources();
        assertNotNull(resources);
        assertFalse(resources.isEmpty());
    }

    // Test double for LdapService with correct method signatures
    private static class MockLdapService extends LdapService {
        private final LoadingCache<String, CachedUser> cache;
        private final com.att.cassandra.security.config.SecurityConfig config;
        MockLdapService(LoadingCache<String, CachedUser> cache, com.att.cassandra.security.config.SecurityConfig config) {
            super((com.att.cassandra.security.config.LdapConfig) null);
            this.cache = cache;
            this.config = config;
        }
        @Override public LoadingCache<String, CachedUser> getCache() { return cache; }
        @Override public com.att.cassandra.security.config.SecurityConfig getConfig() { return config; }
        @Override public java.util.Set<String> fetchUserGroups(String username) {
            // Debug: print cluster and group for troubleshooting
            System.out.println("Cluster: " + TEST_CLUSTER + ", Group: " + TEST_CLUSTER + "-data-ks1-TABLE1-SELECT");
            return java.util.Set.of(TEST_CLUSTER + "-data-ks1-TABLE1-SELECT");
        }
    }
}
