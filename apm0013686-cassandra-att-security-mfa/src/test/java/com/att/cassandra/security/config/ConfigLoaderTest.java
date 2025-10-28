package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ConfigLoaderTest {
    @Test
    void testResolvePluginConfigSuccess() {
        Map<String, Object> plugins = new HashMap<>();
        Map<String, Object> config = new HashMap<>();
        config.put("class", "com.example.MyAuthenticator");
        plugins.put("foo", config);
        Object[] result = ConfigLoader.resolvePluginConfig(plugins, "foo");
        assertEquals("com.example.MyAuthenticator", result[0]);
        assertEquals(config, result[1]);
    }

    @Test
    void testResolvePluginConfigNoLogicalName() {
        Map<String, Object> plugins = new HashMap<>();
        assertThrows(IllegalArgumentException.class, () ->
            ConfigLoader.resolvePluginConfig(plugins, "bar"));
    }

    @Test
    void testResolvePluginConfigNoClass() {
        Map<String, Object> plugins = new HashMap<>();
        Map<String, Object> config = new HashMap<>();
        plugins.put("foo", config);
        assertThrows(IllegalArgumentException.class, () ->
            ConfigLoader.resolvePluginConfig(plugins, "foo"));
    }

    @Test
    void testResolvePluginConfigNotAMap() {
        Map<String, Object> plugins = new HashMap<>();
        plugins.put("foo", "notAMap");
        assertThrows(IllegalArgumentException.class, () ->
            ConfigLoader.resolvePluginConfig(plugins, "foo"));
    }

    @Test
    void testLoadFromWorkingDirectory(@TempDir Path tempDir) throws IOException {
        String originalUserDir = System.getProperty("user.dir");
        try {
            System.setProperty("user.dir", tempDir.toString());
            String fname = "wdconfig.yaml";
            System.setProperty("security.config.filename", fname);
            Path cfg = tempDir.resolve(fname);
            Files.write(cfg, List.of("cache: {}", "externalServices: {}"));
            ConfigLoader.clearTestConfig();
            ConfigLoader.resetForTest();
            SecurityConfig sc = ConfigLoader.load();
            assertNotNull(sc);
        } finally {
            System.setProperty("user.dir", originalUserDir);
        }
    }

    @Test
    void testLoadFromConfDirectory(@TempDir Path tempDir) throws IOException {
        String originalUserDir = System.getProperty("user.dir");
        try {
            System.setProperty("user.dir", tempDir.toString());
            String fname = "security.yaml";
            System.setProperty("security.config.filename", fname);
            Path confDir = tempDir.resolve("conf");
            Files.createDirectory(confDir);
            Path cfg = confDir.resolve(fname);
            Files.write(cfg, List.of("cache: {}", "externalServices: {}"));
            ConfigLoader.clearTestConfig();
            ConfigLoader.resetForTest();
            SecurityConfig sc = ConfigLoader.load();
            assertNotNull(sc);
        } finally {
            System.setProperty("user.dir", originalUserDir);
        }
    }

    @Test
    void testLoadReturnsTestConfig() {
        // Test that load() returns injected testConfig
        SecurityConfig sc = new SecurityConfig();
        ConfigLoader.setTestConfig(sc);
        SecurityConfig loaded = ConfigLoader.load();
        assertSame(sc, loaded);
        assertTrue(ConfigLoader.hasTestConfig());
        ConfigLoader.clearTestConfig();
        assertFalse(ConfigLoader.hasTestConfig());
    }

    @Test
    void testLoadFileNotFoundThrowsRuntimeException() {
        // Ensure RuntimeException thrown when no file found
        String fname = "missing-file-" + System.nanoTime() + ".yaml";
        System.setProperty("security.config.filename", fname);
        ConfigLoader.clearTestConfig();
        ConfigLoader.resetForTest();
        RuntimeException ex = assertThrows(RuntimeException.class, ConfigLoader::load);
        assertTrue(ex.getMessage().contains(fname));
    }

    @Test
    void testLoadFromClasspathResource() {
        // Should load security.yaml from classpath (src/test/resources)
        ConfigLoader.clearTestConfig();
        ConfigLoader.resetForTest();
        System.clearProperty("security.config.filename");
        SecurityConfig sc = ConfigLoader.load();
        assertNotNull(sc, "SecurityConfig should be loaded from classpath resource");
        assertNotNull(sc.getCache(), "CacheConfig should be present");
        assertEquals(1, sc.getCache().getTtlSeconds());
    }

    @Test
    void testResetForTestClearsTestConfig() {
        SecurityConfig cfg = new SecurityConfig();
        ConfigLoader.setTestConfig(cfg);
        assertTrue(ConfigLoader.hasTestConfig(), "Test config should be set");
        ConfigLoader.resetForTest();
        assertFalse(ConfigLoader.hasTestConfig(), "resetForTest should clear test config");
    }

    @Test
    void testLoadInvalidYamlThrows(@TempDir Path tempDir) throws IOException {
        String originalUserDir = System.getProperty("user.dir");
        try {
            System.setProperty("user.dir", tempDir.toString());
            String fname = "bad.yaml";
            System.setProperty("security.config.filename", fname);
            Path bad = tempDir.resolve(fname);
            // Write invalid YAML
            Files.write(bad, List.of("not: [valid: yaml"));
            ConfigLoader.clearTestConfig();
            ConfigLoader.resetForTest();
            RuntimeException ex = assertThrows(RuntimeException.class, ConfigLoader::load);
            assertTrue(ex.getMessage().contains("Failed to load configuration"));
        } finally {
            System.setProperty("user.dir", originalUserDir);
        }
    }

    @Test
    void testLoadWithNullContextClassLoader() {
        // Simulate null context class loader to hit fallback to ConfigLoader.class loader
        ClassLoader origCl = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(null);
            System.clearProperty("security.config.filename");
            ConfigLoader.clearTestConfig();
            ConfigLoader.resetForTest();
            SecurityConfig sc = ConfigLoader.load();
            assertNotNull(sc, "Should load from classpath via default class loader fallback");
        } finally {
            Thread.currentThread().setContextClassLoader(origCl);
        }
    }
}
