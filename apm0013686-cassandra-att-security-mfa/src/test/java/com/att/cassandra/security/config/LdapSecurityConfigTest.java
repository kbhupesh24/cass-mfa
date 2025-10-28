package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LdapSecurityConfigTest {
    @Test
    void testGettersAndSetters() {
        LdapSecurityConfig config = new LdapSecurityConfig();
        LdapConfig ldap = new LdapConfig();
        CacheConfig cache = new CacheConfig();
        JwtConfig jwt = new JwtConfig();
        KeyspaceRolesConfig keyspace = new KeyspaceRolesConfig();
        java.util.List<KeyspaceRolesConfig> keyspaces = java.util.List.of(keyspace);
        java.util.List<RoleConfig> defaultRoles = java.util.List.of(new RoleConfig());

        config.setLdap(ldap);
        config.setCache(cache);
        config.setJwt(jwt);
        config.setKeyspace(keyspace);
        config.setKeyspaces(keyspaces);
        config.setDefaultRoles(defaultRoles);

        assertSame(ldap, config.getLdap());
        assertSame(cache, config.getCache());
        assertSame(jwt, config.getJwt());
        assertSame(keyspace, config.getKeyspace());
        assertSame(keyspaces, config.getKeyspaces());
        assertSame(defaultRoles, config.getDefaultRoles());
    }
}
