package com.att.cassandra.security.auth;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.IResource;
import java.util.Set;

/**
 * Unit tests for ChainedAuthorizer using real YAML configurations in test resources.
 */
class ChainedAuthorizerTest {

    @Test
    void testValidateConfigurationNoOp() throws Exception {
        new ChainedAuthorizer().validateConfiguration();
    }

    @Test
    void testSetupFailsWhenNoConfig() {
        System.setProperty("security.config.filename", "empty-config.yaml");
        ChainedAuthorizer authz = new ChainedAuthorizer();
        assertThrows(IllegalStateException.class, authz::setup);
        System.clearProperty("security.config.filename");
    }

    @Test
    void testSetupAndAuthorizeMergesPermissionsAndHandlesExceptions() throws Exception {
        System.setProperty("security.config.filename", "chained-config.yaml");
        ChainedAuthorizer authz = new ChainedAuthorizer();
        authz.setup();
        AuthenticatedUser user = new AuthenticatedUser("u");
        IResource resource = DataResource.table("ks", "tbl");
        Set<Permission> perms = authz.authorize(user, resource);
        assertTrue(perms.contains(Permission.SELECT));
        assertTrue(perms.contains(Permission.MODIFY));
        System.clearProperty("security.config.filename");
    }

    @Test
    void testUnsupportedOperations() {
        ChainedAuthorizer authz = new ChainedAuthorizer();
        AuthenticatedUser user = new AuthenticatedUser("u");
        Set<Permission> perms = Set.of(Permission.SELECT);
        IResource res = DataResource.table("ks", "tbl");
        RoleResource rr = RoleResource.role("r");
        assertThrows(UnsupportedOperationException.class, () -> authz.grant(user, perms, res, rr));
        assertThrows(UnsupportedOperationException.class, () -> authz.list(user, perms, res, rr));
        assertThrows(UnsupportedOperationException.class, () -> authz.revoke(user, perms, res, rr));
        assertThrows(UnsupportedOperationException.class, () -> authz.revokeAllFrom(rr));
        assertThrows(UnsupportedOperationException.class, () -> authz.revokeAllOn(res));
    }

    @Test
    void testProtectedResourcesAggregates() throws Exception {
        System.setProperty("security.config.filename", "chained-config.yaml");
        ChainedAuthorizer authz = new ChainedAuthorizer();
        authz.setup();
        Set<? extends IResource> resources = authz.protectedResources();
        assertEquals(TestAuthA.PROTECTED, resources);
        System.clearProperty("security.config.filename");
    }

    // Nested test authorizers referenced by chained-config.yaml
    public static class TestAuthA implements org.apache.cassandra.auth.IAuthorizer {
        static final Set<IResource> PROTECTED = Set.of(DataResource.keyspace("ks"));
        public TestAuthA(String name) {}
        public TestAuthA() {}
        @Override public void validateConfiguration() {}
        @Override public void setup() {}
        @Override public java.util.Set<Permission> authorize(AuthenticatedUser u, IResource r) { return Set.of(Permission.SELECT); }
        @Override public java.util.Set<org.apache.cassandra.auth.Permission> grant(AuthenticatedUser u, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { return Set.of(); }
        @Override public java.util.Set<org.apache.cassandra.auth.PermissionDetails> list(AuthenticatedUser performer, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { return Set.of(); }
        @Override public java.util.Set<org.apache.cassandra.auth.Permission> revoke(AuthenticatedUser u, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { return Set.of(); }
        @Override public void revokeAllFrom(RoleResource role) {}
        @Override public void revokeAllOn(IResource resource) {}
        @Override public java.util.Set<? extends IResource> protectedResources() { return PROTECTED; }
    }
    public static class TestAuthB implements org.apache.cassandra.auth.IAuthorizer {
        public TestAuthB(String name) {}
        public TestAuthB() {}
        @Override public void validateConfiguration() {}
        @Override public void setup() {}
        @Override public java.util.Set<Permission> authorize(AuthenticatedUser u, IResource r) { return Set.of(Permission.MODIFY); }
        @Override public java.util.Set<org.apache.cassandra.auth.Permission> grant(AuthenticatedUser u, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { throw new UnsupportedOperationException(); }
        @Override public java.util.Set<org.apache.cassandra.auth.PermissionDetails> list(AuthenticatedUser performer, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { throw new UnsupportedOperationException(); }
        @Override public java.util.Set<org.apache.cassandra.auth.Permission> revoke(AuthenticatedUser u, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { throw new UnsupportedOperationException(); }
        @Override public void revokeAllFrom(RoleResource role) {}
        @Override public void revokeAllOn(IResource resource) {}
        @Override public java.util.Set<? extends IResource> protectedResources() { return Set.of(); }
    }
    public static class TestAuthThrows implements org.apache.cassandra.auth.IAuthorizer {
        public TestAuthThrows(String name) {}
        public TestAuthThrows() {}
        @Override public void validateConfiguration() {}
        @Override public void setup() {}
        @Override public java.util.Set<Permission> authorize(AuthenticatedUser u, IResource r) { throw new RuntimeException("fail"); }
        @Override public java.util.Set<org.apache.cassandra.auth.Permission> grant(AuthenticatedUser u, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { throw new UnsupportedOperationException(); }
        @Override public java.util.Set<org.apache.cassandra.auth.PermissionDetails> list(AuthenticatedUser performer, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { throw new UnsupportedOperationException(); }
        @Override public java.util.Set<org.apache.cassandra.auth.Permission> revoke(AuthenticatedUser u, java.util.Set<Permission> permissions, IResource resource, RoleResource grantee) { throw new UnsupportedOperationException(); }
        @Override public void revokeAllFrom(RoleResource role) {}
        @Override public void revokeAllOn(IResource resource) {}
        @Override public java.util.Set<? extends IResource> protectedResources() { return Set.of(); }
    }
}
