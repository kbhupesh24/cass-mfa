package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LdapConfigTest {
    @Test
    void testGettersAndSetters() {
        LdapConfig config = new LdapConfig();
        config.setUrl("ldap://localhost");
        config.setUserDnPattern("uid={0},ou=users,dc=example,dc=com");
        config.setBindUser("admin");
        config.setBindPassword("secret");
        config.setGroupBaseDn("ou=groups,dc=example,dc=com");
        config.setGroupAttribute("cn");

        assertEquals("ldap://localhost", config.getUrl());
        assertEquals("uid={0},ou=users,dc=example,dc=com", config.getUserDnPattern());
        assertEquals("admin", config.getBindUser());
        assertEquals("secret", config.getBindPassword());
        assertEquals("ou=groups,dc=example,dc=com", config.getGroupBaseDn());
        assertEquals("cn", config.getGroupAttribute());
    }
}
