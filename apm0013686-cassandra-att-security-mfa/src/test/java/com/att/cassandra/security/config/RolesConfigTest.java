package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RolesConfigTest {
    @Test
    void testKeyspaceRolesConfigGettersAndSetters() {
        KeyspaceRolesConfig ksConfig = new KeyspaceRolesConfig();
        ksConfig.setName("ks1");
        ksConfig.setRolePrefix("prefix-");
        java.util.List<RoleConfig> roles = java.util.List.of(new RoleConfig());
        ksConfig.setRoles(roles);
        assertEquals("ks1", ksConfig.getName());
        assertEquals("prefix-", ksConfig.getRolePrefix());
        assertSame(roles, ksConfig.getRoles());
    }
}
