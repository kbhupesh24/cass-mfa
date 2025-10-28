package com.att.cassandra.security.auth.util;

import com.att.cassandra.security.config.KeyspaceRolesConfig;
import com.att.cassandra.security.config.ResourcePermissionConfig;
import com.att.cassandra.security.config.RoleConfig;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class RolePermissionMapperTest {
    @Test
    void testNullRolePrefixUsesEmptyPrefix() {
        // defaultRoles fallback with empty prefix should yield no permissions for unknown role name
        List<KeyspaceRolesConfig> keyspaces = Collections.emptyList();
        List<RoleConfig> defaultRoles = Collections.singletonList(new RoleConfig());
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            Arrays.asList("any"), DataResource.table("ks","tbl"), keyspaces, defaultRoles);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testExpectedPrefixAddsDashAndMatches() {
        // config for keyspace with prefix without dash
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks1");
        ksc.setRolePrefix("PREF");
        RoleConfig role = new RoleConfig();
        role.setName("role1");
        ResourcePermissionConfig rpc = new ResourcePermissionConfig();
        rpc.setType("data"); rpc.setName("*"); rpc.setPermissions(List.of("SELECT"));
        role.setResources(List.of(rpc));
        ksc.setRoles(List.of(role));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Collection<String> groups = List.of("PREF-role1");
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            groups, DataResource.table("ks1","tbl1"), keyspaces, null);
        assertEquals(Set.of(Permission.SELECT), perms);
    }

    @Test
    void testGroupSkippingNoPrefix() {
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks1"); ksc.setRolePrefix("P-");
        // roles list can be empty
        ksc.setRoles(Collections.emptyList());
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("X-role"), DataResource.table("ks1","tbl"), keyspaces, null);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testRoleNotFound() {
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks1"); ksc.setRolePrefix("RP-");
        // roles list does not contain 'unknown'
        RoleConfig rc = new RoleConfig(); rc.setName("other");
        ksc.setRoles(List.of(rc));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("RP-unknown"), DataResource.table("ks1","tbl"), keyspaces, null);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testDataResourceNameMatchSpecificTable() {
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks"); ksc.setRolePrefix("R-");
        RoleConfig role = new RoleConfig(); role.setName("r");
        ResourcePermissionConfig rpc = new ResourcePermissionConfig();
        rpc.setType("data"); rpc.setName("tbl2"); rpc.setPermissions(List.of("MODIFY"));
        role.setResources(List.of(rpc));
        ksc.setRoles(List.of(role));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Collection<String> groups = List.of("R-r");
        // matching table
        Set<Permission> p1 = RolePermissionMapper.mapGroupsToPermissions(
            groups, DataResource.table("ks","tbl2"), keyspaces, null);
        assertEquals(Set.of(Permission.MODIFY), p1);
        // non-matching table
        Set<Permission> p2 = RolePermissionMapper.mapGroupsToPermissions(
            groups, DataResource.table("ks","tblX"), keyspaces, null);
        assertTrue(p2.isEmpty());
    }

    @Test
    void testGroupsNullReturnsEmpty() {
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks"); ksc.setRolePrefix("P-"); ksc.setRoles(Collections.emptyList());
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            null, DataResource.table("ks","tbl"), keyspaces, null);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testPrefixAlreadyWithDashAndMultiplePermissions() {
        // rolePrefix ends with dash, rpc has multiple permissions
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ksX"); ksc.setRolePrefix("RP-");
        RoleConfig role = new RoleConfig(); role.setName("roleX");
        ResourcePermissionConfig rpc1 = new ResourcePermissionConfig();
        rpc1.setType("data"); rpc1.setName("*"); rpc1.setPermissions(List.of("SELECT","MODIFY"));
        role.setResources(List.of(rpc1)); ksc.setRoles(List.of(role));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("RP-roleX"), DataResource.table("ksX","table"), keyspaces, null);
        assertEquals(Set.of(Permission.SELECT, Permission.MODIFY), perms);
    }

    @Test
    void testInvalidPermissionIgnored() {
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ksY"); ksc.setRolePrefix("PX-");
        RoleConfig role = new RoleConfig(); role.setName("rY");
        ResourcePermissionConfig rpc = new ResourcePermissionConfig();
        rpc.setType("data"); rpc.setName("*"); rpc.setPermissions(List.of("INVALID", "AUTHORIZE"));
        role.setResources(List.of(rpc)); ksc.setRoles(List.of(role));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("PX-rY"), DataResource.table("ksY","tbl"), keyspaces, null);
        assertEquals(Set.of(Permission.AUTHORIZE), perms);
    }

    @Test
    void testKeyspacesNullReturnsEmpty() {
        // null keyspaces should use defaultRoles fallback (empty list) and yield no permissions
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("any"), DataResource.table("ks","tbl"), null, Collections.emptyList());
        assertTrue(perms.isEmpty());
    }

    @Test
    void testTypeMismatchSkipsPermissions() {
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks"); ksc.setRolePrefix("R-");
        RoleConfig role = new RoleConfig(); role.setName("r1");
        ResourcePermissionConfig rpc = new ResourcePermissionConfig();
        rpc.setType("other"); rpc.setName("*"); rpc.setPermissions(List.of("SELECT"));
        role.setResources(List.of(rpc)); ksc.setRoles(List.of(role));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("R-r1"), DataResource.table("ks","tbl"), keyspaces, null);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testNonDataResourceTypeAndNameMatches() {
        // non-DataResource branch: type and name both match
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ksR"); ksc.setRolePrefix("PX-");
        ResourcePermissionConfig rpc = new ResourcePermissionConfig();
        rpc.setType("type"); rpc.setName("nam"); rpc.setPermissions(List.of("AUTHORIZE"));
        RoleConfig role = new RoleConfig(); role.setName("roleR"); role.setResources(List.of(rpc));
        ksc.setRoles(List.of(role));
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Collection<String> groups = List.of("PX-roleR");
        IResource resource = new IResource() {
            @Override public String getName() { return "typeXYZnamPQR"; }
            @Override public boolean exists() { return false; }
            @Override public boolean hasParent() { return false; }
            @Override public IResource getParent() { return null; }
            @Override public Set<Permission> applicablePermissions() { return Collections.emptySet(); }
        };
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(groups, resource, keyspaces, null);
        assertEquals(Set.of(Permission.AUTHORIZE), perms);
    }

    @Test
    void testKeyspaceListNoMatchReturnsEmpty() {
        // non-matching keyspace config and no defaultRoles yields empty permissions
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("other"); ksc.setRolePrefix("X-"); ksc.setRoles(Collections.emptyList());
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("X-role"), DataResource.table("ks","tbl"), keyspaces, null);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testDefaultRolesMapping() {
        // defaultRoles fallback mapping with empty prefix
        RoleConfig defRole = new RoleConfig();
        defRole.setName("def");
        ResourcePermissionConfig rpc = new ResourcePermissionConfig();
        rpc.setType("data"); rpc.setName("*"); rpc.setPermissions(List.of("SELECT"));
        defRole.setResources(List.of(rpc));
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("def"), DataResource.table("ks","t"), null, List.of(defRole));
        assertEquals(Set.of(Permission.SELECT), perms);
    }

    @Test
    void testRolesNullReturnsEmpty() {
        // ksConfig roles null should result in empty permissions
        KeyspaceRolesConfig ksc = new KeyspaceRolesConfig();
        ksc.setName("ks"); ksc.setRolePrefix("RP-"); // roles not set, null
        List<KeyspaceRolesConfig> keyspaces = List.of(ksc);
        Set<Permission> perms = RolePermissionMapper.mapGroupsToPermissions(
            List.of("RP-any"), DataResource.table("ks","tbl"), keyspaces, null);
        assertTrue(perms.isEmpty());
    }

    @Test
    void testPrivateConstructorThrows() throws Exception {
        Constructor<RolePermissionMapper> ctor = RolePermissionMapper.class.getDeclaredConstructor();
        ctor.setAccessible(true);
        InvocationTargetException ex = assertThrows(InvocationTargetException.class, () -> ctor.newInstance());
        assertTrue(ex.getCause() instanceof UnsupportedOperationException, "Expected UnsupportedOperationException as cause");
    }
}
