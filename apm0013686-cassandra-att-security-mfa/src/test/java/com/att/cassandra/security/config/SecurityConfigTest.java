package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SecurityConfigTest {
    @Test
    void testGettersAndSetters() {
        SecurityConfig config = new SecurityConfig();
        CacheConfig cache = new CacheConfig();
        ChainedConfig chained = new ChainedConfig();
        Map<String, Object> authenticators = new HashMap<>();
        Map<String, Object> authorizers = new HashMap<>();
        Map<String, Object> externalServices = new HashMap<>();
        List<String> internalUsers = Arrays.asList("alice", "bob");
        List<KeyspaceRolesConfig> keyspaces = List.of(new KeyspaceRolesConfig());
        List<RoleConfig> defaultRoles = List.of(new RoleConfig());

        config.setCache(cache);
        config.setChained(chained);
        config.setAuthenticators(authenticators);
        config.setAuthorizers(authorizers);
        config.setExternalServices(externalServices);
        config.setInternalUsers(internalUsers);
        config.setKeyspaces(keyspaces);
        config.setDefaultRoles(defaultRoles);

        assertSame(cache, config.getCache());
        assertSame(chained, config.getChained());
        assertSame(authenticators, config.getAuthenticators());
        assertSame(authorizers, config.getAuthorizers());
        assertSame(externalServices, config.getExternalServices());
        assertSame(internalUsers, config.getInternalUsers());
        assertSame(keyspaces, config.getKeyspaces());
        assertSame(defaultRoles, config.getDefaultRoles());
    }

    @Test
    void testValidateThrowsIfMissingAuthenticatorsOrAuthorizers() {
        SecurityConfig config = new SecurityConfig();
        // Both null
        assertThrows(RuntimeException.class, config::validate);
        // Only authenticators set
        config.setAuthenticators(new HashMap<>());
        assertThrows(RuntimeException.class, config::validate);
        // Only authorizers set
        config.setAuthenticators(null);
        config.setAuthorizers(new HashMap<>());
        assertThrows(RuntimeException.class, config::validate);
        // Both set
        config.setAuthenticators(new HashMap<>() {{ put("foo", new Object()); }});
        config.setAuthorizers(new HashMap<>() {{ put("bar", new Object()); }});
        assertDoesNotThrow(config::validate);
    }

    @Test
    void testGetExternalServiceConfigErrors() {
        // Null config
        SecurityConfig config = new SecurityConfig();
        com.att.cassandra.security.config.ConfigLoader.setTestConfig(config);
        assertThrows(IllegalArgumentException.class, () -> SecurityConfig.getExternalServiceConfig("foo"));
        // Not a map
        config.setExternalServices(Map.of("foo", "notAMap"));
        com.att.cassandra.security.config.ConfigLoader.setTestConfig(config);
        assertThrows(IllegalArgumentException.class, () -> SecurityConfig.getExternalServiceConfig("foo"));
        // No such logical name
        config.setExternalServices(Map.of());
        com.att.cassandra.security.config.ConfigLoader.setTestConfig(config);
        assertThrows(IllegalArgumentException.class, () -> SecurityConfig.getExternalServiceConfig("foo"));
        com.att.cassandra.security.config.ConfigLoader.clearTestConfig();
    }

    @Test
    void testGetExternalServiceConfigSuccess() {
        Map<String, Object> serviceConfig = Map.of("jwksUrl", "url");
        SecurityConfig config = new SecurityConfig();
        config.setExternalServices(Map.of("foo", serviceConfig));
        com.att.cassandra.security.config.ConfigLoader.setTestConfig(config);
        Map<String, Object> result = SecurityConfig.getExternalServiceConfig("foo");
        assertSame(serviceConfig, result);
        com.att.cassandra.security.config.ConfigLoader.clearTestConfig();
    }

        @Test
    void testGetExternalServiceConfigThrowsOnMissing() {
        SecurityConfig config = new SecurityConfig();
        config.setExternalServices(Collections.emptyMap());
        ConfigLoader.setTestConfig(config);
        assertThrows(IllegalArgumentException.class, () -> SecurityConfig.getExternalServiceConfig("missing"));
        ConfigLoader.clearTestConfig();
    }

    @Test
    void testGetExternalServiceConfigThrowsOnNotAMap() {
        SecurityConfig config = new SecurityConfig();
        config.setExternalServices(Map.of("foo", "notAMap"));
        ConfigLoader.setTestConfig(config);
        assertThrows(IllegalArgumentException.class, () -> SecurityConfig.getExternalServiceConfig("foo"));
        ConfigLoader.clearTestConfig();
    }

}
