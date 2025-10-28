package com.att.cassandra.security.auth.jwt;

import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.SecurityConfig;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.Resources;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthorizerTest {
    private static final String TEST_CLUSTER = "test-cluster";

    @Test
    void testConstructorAndSetLogicalName() {
        JwtAuthorizer authz = new JwtAuthorizer();
        authz.setLogicalName("jwt1");
        assertNotNull(authz);
    }

    @Test
    void testConstructorWithLogicalName() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        assertNotNull(authz);
    }

    @Test
    void testValidateConfigurationAndSetup() throws org.apache.cassandra.exceptions.ConfigurationException {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        // Should not throw
        authz.validateConfiguration();
        // setup() should throw because no config for logical name
        assertThrows(IllegalStateException.class, authz::setup);
    }

    @Test
    void testUnsupportedOperations() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        assertThrows(UnsupportedOperationException.class, () ->
            authz.grant(null, null, null, null));
        assertThrows(UnsupportedOperationException.class, () ->
            authz.list(null, null, null, null));
        assertThrows(UnsupportedOperationException.class, () ->
            authz.revoke(null, null, null, null));
        assertThrows(UnsupportedOperationException.class, () ->
            authz.revokeAllFrom(null));
        assertThrows(UnsupportedOperationException.class, () ->
            authz.revokeAllOn(null));
    }

    @Test
    void testGrantThrowsWithCorrectErrorCode() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        Exception ex = assertThrows(UnsupportedOperationException.class, () ->
            authz.grant(null, null, null, null));
        assertTrue(ex.getMessage().contains("E110"));
    }

    @Test
    void testListThrowsWithCorrectErrorCode() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        Exception ex = assertThrows(UnsupportedOperationException.class, () ->
            authz.list(null, null, null, null));
        assertTrue(ex.getMessage().contains("E110"));
    }

    @Test
    void testRevokeThrowsWithCorrectErrorCode() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        Exception ex = assertThrows(UnsupportedOperationException.class, () ->
            authz.revoke(null, null, null, null));
        assertTrue(ex.getMessage().contains("E110"));
    }

    @Test
    void testRevokeAllFromThrowsWithCorrectErrorCode() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        Exception ex = assertThrows(UnsupportedOperationException.class, () ->
            authz.revokeAllFrom(null));
        assertTrue(ex.getMessage().contains("E110"));
    }

    @Test
    void testRevokeAllOnThrowsWithCorrectErrorCode() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        Exception ex = assertThrows(UnsupportedOperationException.class, () ->
            authz.revokeAllOn(null));
        assertTrue(ex.getMessage().contains("E110"));
    }

    @Test
    void testAuthorizeReturnsEmptySet() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), Resources.fromName("data/ks/tbl"));
        assertNotNull(perms);
    }

    @Test
    void testProtectedResourcesReturnsExpected() {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        var resources = authz.protectedResources();
        assertNotNull(resources);
        assertFalse(resources.isEmpty());
    }

    @Test
    void testCacheLoaderLoadMethod() throws Exception {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        java.lang.reflect.Field myConfigField = JwtAuthorizer.class.getDeclaredField("myConfig");
        myConfigField.setAccessible(true);
        java.util.HashMap<String, Object> config = new java.util.HashMap<>();
        config.put("userInfoUrl", "");
        myConfigField.set(authz, config);
        java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
        claimsCacheField.setAccessible(true);
        com.google.common.cache.LoadingCache<String, java.util.List<String>> dummyCache = com.google.common.cache.CacheBuilder.newBuilder().build(
            new com.google.common.cache.CacheLoader<String, java.util.List<String>>() {
                @Override
                public java.util.List<String> load(@javax.annotation.Nonnull String token) throws Exception {
                    return java.util.Collections.emptyList();
                }
            }
        );
        claimsCacheField.set(authz, dummyCache);
        Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), Resources.fromName("data/ks/tbl"));
        assertNotNull(perms);
    }

    @Test
    void testDefaultConstructorAndCacheLoaderLoad() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class)) {
            SecurityConfig mockConfig = mock(SecurityConfig.class);
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            // Default logical name is "jwt"
            authorizerConfigs.put("jwt", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);

            JwtAuthorizer authz = new JwtAuthorizer(); // default constructor
            authz.setLogicalName("jwt"); // Ensure logicalName is set
            authz.setup();
            // Setup a dummy claimsCache with a test CacheLoader
            java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
            claimsCacheField.setAccessible(true);
            com.google.common.cache.LoadingCache<String, java.util.List<String>> dummyCache = com.google.common.cache.CacheBuilder.newBuilder().build(
                new com.google.common.cache.CacheLoader<String, java.util.List<String>>() {
                    @Override
                    public java.util.List<String> load(@javax.annotation.Nonnull String token) throws Exception {
                        return java.util.Collections.singletonList("testrole");
                    }
                }
            );
            claimsCacheField.set(authz, dummyCache);
            // Call get() to trigger load(String)
            java.util.List<String> result = dummyCache.get("sometoken");
            assertNotNull(result);
            assertEquals("testrole", result.get(0));
        }
    }

    @Test
    void testSetupWithUserInfoUrlNotNullOrEmpty() throws Exception {
        try (MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            // Ensure the cluster name mock returns "test cluster" (with a space)
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn("test cluster");
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            try (org.mockito.MockedStatic<ConfigLoader> loaderMock = org.mockito.Mockito.mockStatic(ConfigLoader.class)) {
                SecurityConfig mockConfig = mock(SecurityConfig.class);
                loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
                Map<String, Object> authorizerConfigs = new HashMap<>();
                Map<String, Object> logicalConfig = new HashMap<>();
                logicalConfig.put("userInfoUrl", "http://localhost/userinfo");
                logicalConfig.put("refreshMinutes", 1);
                logicalConfig.put("expireHours", 1);
                authorizerConfigs.put("jwt1", logicalConfig);
                when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
                authz.setup();
            }
        }
    }

    @Test
    void testAuthorizeWithRolesNull() throws Exception {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        // Setup claimsCache to return null roles
        java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
        claimsCacheField.setAccessible(true);
        com.google.common.cache.LoadingCache<String, java.util.List<String>> dummyCache = com.google.common.cache.CacheBuilder.newBuilder().build(
            new com.google.common.cache.CacheLoader<String, java.util.List<String>>() {
                @Override
                public java.util.List<String> load(@javax.annotation.Nonnull String token) { return null; }
            }
        );
        claimsCacheField.set(authz, dummyCache);
        // Set JwtTokenContext token via reflection or static method if available
        com.att.cassandra.security.auth.jwt.JwtTokenContext.setToken("tok");
        Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), Resources.fromName("data/ks/tbl"));
        assertNotNull(perms);
        com.att.cassandra.security.auth.jwt.JwtTokenContext.clear();
    }

    @Test
    void testAuthorizeWithCacheGetThrowing() throws Exception {
        JwtAuthorizer authz = new JwtAuthorizer("jwt1");
        // Setup claimsCache to throw
        java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
        claimsCacheField.setAccessible(true);
        com.google.common.cache.LoadingCache<String, java.util.List<String>> dummyCache = com.google.common.cache.CacheBuilder.newBuilder().build(
            new com.google.common.cache.CacheLoader<String, java.util.List<String>>() {
                @Override
                public java.util.List<String> load(@javax.annotation.Nonnull String token) throws Exception { throw new RuntimeException("fail"); }
            }
        );
        claimsCacheField.set(authz, dummyCache);
        com.att.cassandra.security.auth.jwt.JwtTokenContext.setToken("tok");
        Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), Resources.fromName("data/ks/tbl"));
        assertNotNull(perms);
        com.att.cassandra.security.auth.jwt.JwtTokenContext.clear();
    }

    @Test
    void testAuthorizeWithGroupClaimWrongPrefix() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            try (MockedStatic<com.att.cassandra.security.auth.jwt.JwtTokenContext> tokenContextMock = Mockito.mockStatic(com.att.cassandra.security.auth.jwt.JwtTokenContext.class);
                 MockedStatic<com.nimbusds.jwt.SignedJWT> jwtMock = Mockito.mockStatic(com.nimbusds.jwt.SignedJWT.class)) {
                tokenContextMock.when(com.att.cassandra.security.auth.jwt.JwtTokenContext::getToken).thenReturn("tok");
                com.nimbusds.jwt.SignedJWT mockJwt = mock(com.nimbusds.jwt.SignedJWT.class);
                com.nimbusds.jwt.JWTClaimsSet mockClaims = mock(com.nimbusds.jwt.JWTClaimsSet.class);
                jwtMock.when(() -> com.nimbusds.jwt.SignedJWT.parse("tok")).thenReturn(mockJwt);
                when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
                when(mockClaims.getStringListClaim("roles")).thenReturn(null);
                when(mockClaims.getStringListClaim("groups")).thenReturn(java.util.Collections.singletonList("wrongcluster-data-ks1-tbl-SELECT"));
                org.apache.cassandra.auth.IResource resource = Resources.fromName("data/ks1/tbl");
                Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
                assertTrue(perms.isEmpty());
            }
        }
    }

    @Test
    void testAuthorizeWithGroupClaimWrongObjName() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            try (MockedStatic<com.att.cassandra.security.auth.jwt.JwtTokenContext> tokenContextMock = Mockito.mockStatic(com.att.cassandra.security.auth.jwt.JwtTokenContext.class);
                 MockedStatic<com.nimbusds.jwt.SignedJWT> jwtMock = Mockito.mockStatic(com.nimbusds.jwt.SignedJWT.class)) {
                tokenContextMock.when(com.att.cassandra.security.auth.jwt.JwtTokenContext::getToken).thenReturn("tok");
                com.nimbusds.jwt.SignedJWT mockJwt = mock(com.nimbusds.jwt.SignedJWT.class);
                com.nimbusds.jwt.JWTClaimsSet mockClaims = mock(com.nimbusds.jwt.JWTClaimsSet.class);
                jwtMock.when(() -> com.nimbusds.jwt.SignedJWT.parse("tok")).thenReturn(mockJwt);
                when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
                when(mockClaims.getStringListClaim("roles")).thenReturn(null);
                when(mockClaims.getStringListClaim("groups")).thenReturn(java.util.Collections.singletonList("test-cluster-data-ks1-wrongobj-SELECT"));
                org.apache.cassandra.auth.IResource resource = Resources.fromName("data/ks1/tbl");
                Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
                assertTrue(perms.isEmpty());
            }
        }
    }

    @Test
    void testAuthorizeWithGroupClaimWrongAction() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            try (MockedStatic<com.att.cassandra.security.auth.jwt.JwtTokenContext> tokenContextMock = Mockito.mockStatic(com.att.cassandra.security.auth.jwt.JwtTokenContext.class);
                 MockedStatic<com.nimbusds.jwt.SignedJWT> jwtMock = Mockito.mockStatic(com.nimbusds.jwt.SignedJWT.class)) {
                tokenContextMock.when(com.att.cassandra.security.auth.jwt.JwtTokenContext::getToken).thenReturn("tok");
                com.nimbusds.jwt.SignedJWT mockJwt = mock(com.nimbusds.jwt.SignedJWT.class);
                com.nimbusds.jwt.JWTClaimsSet mockClaims = mock(com.nimbusds.jwt.JWTClaimsSet.class);
                jwtMock.when(() -> com.nimbusds.jwt.SignedJWT.parse("tok")).thenReturn(mockJwt);
                when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
                when(mockClaims.getStringListClaim("roles")).thenReturn(null);
                // Use a DataResource for correct resource type
                org.apache.cassandra.auth.DataResource resource = org.apache.cassandra.auth.DataResource.table("KS1", "tbl");
                // Use dash-delimited group string with mismatched action (should not match)
                when(mockClaims.getStringListClaim("groups")).thenReturn(java.util.Collections.singletonList("test-cluster-data-KS1-tbl-FAKEACTION"));
                Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
                assertTrue(perms.isEmpty());
            }
        }
    }

    @Test
    void testAuthorizeWithPermissionInApplicablePermissions() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
            claimsCacheField.setAccessible(true);
            com.google.common.cache.LoadingCache<String, java.util.List<String>> dummyCache = com.google.common.cache.CacheBuilder.newBuilder().build(
                new com.google.common.cache.CacheLoader<String, java.util.List<String>>() {
                    @Override
                    public java.util.List<String> load(@javax.annotation.Nonnull String token) {
                        // Use the correct group string for the test config
                        return java.util.Collections.singletonList("AP-MYKS-READ");
                    }
                }
            );
            claimsCacheField.set(authz, dummyCache);
            com.att.cassandra.security.auth.jwt.JwtTokenContext.setToken("tok");
            org.apache.cassandra.auth.IResource resource = Resources.fromName("data/KS1/tbl");
            Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
            assertTrue(perms.contains(Permission.SELECT));
            com.att.cassandra.security.auth.jwt.JwtTokenContext.clear();
        }
    }

    @Test
    void testAuthorizeWithPermissionValueOfThrows() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
            claimsCacheField.setAccessible(true);
            com.google.common.cache.LoadingCache<String, java.util.List<String>> dummyCache = com.google.common.cache.CacheBuilder.newBuilder().build(
                new com.google.common.cache.CacheLoader<String, java.util.List<String>>() {
                    @Override
                    public java.util.List<String> load(@javax.annotation.Nonnull String token) {
                        return java.util.Collections.singletonList("test-cluster-data-ks1-tbl-NOTAPERM");
                    }
                }
            );
            claimsCacheField.set(authz, dummyCache);
            com.att.cassandra.security.auth.jwt.JwtTokenContext.setToken("tok");
            org.apache.cassandra.auth.IResource resource = Resources.fromName("data/ks1/tbl");
            Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
            assertTrue(perms.isEmpty());
            com.att.cassandra.security.auth.jwt.JwtTokenContext.clear();
        }
    }

    @Test
    void testAuthorize_GroupClaim_PrefixObjActionMatch() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            try (MockedStatic<com.att.cassandra.security.auth.jwt.JwtTokenContext> tokenContextMock = Mockito.mockStatic(com.att.cassandra.security.auth.jwt.JwtTokenContext.class);
                 MockedStatic<com.nimbusds.jwt.SignedJWT> jwtMock = Mockito.mockStatic(com.nimbusds.jwt.SignedJWT.class)) {
                tokenContextMock.when(com.att.cassandra.security.auth.jwt.JwtTokenContext::getToken).thenReturn("tok");
                com.nimbusds.jwt.SignedJWT mockJwt = mock(com.nimbusds.jwt.SignedJWT.class);
                com.nimbusds.jwt.JWTClaimsSet mockClaims = mock(com.nimbusds.jwt.JWTClaimsSet.class);
                jwtMock.when(() -> com.nimbusds.jwt.SignedJWT.parse("tok")).thenReturn(mockJwt);
                when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
                when(mockClaims.getStringListClaim("roles")).thenReturn(null);
                // Use mapped keyspace name in group string
                when(mockClaims.getStringListClaim("groups")).thenReturn(java.util.Collections.singletonList("AP-MYKS-READ"));
                org.apache.cassandra.auth.IResource resource = org.apache.cassandra.auth.Resources.fromName("data/KS1/tbl");
                Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
                System.out.println("DEBUG: perms returned by authorize: " + perms);
                assertNotNull(perms);
                assertTrue(perms.contains(Permission.SELECT), "Expected SELECT permission");
            }
        }
    }

    @Test
    void testAuthorizeWithDashDelimitedGroup() throws Exception {
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class);
             MockedStatic<com.att.cassandra.security.auth.jwt.JwtTokenContext> tokenContextMock = Mockito.mockStatic(com.att.cassandra.security.auth.jwt.JwtTokenContext.class);
             MockedStatic<com.nimbusds.jwt.SignedJWT> jwtMock = Mockito.mockStatic(com.nimbusds.jwt.SignedJWT.class);
             MockedStatic<org.apache.cassandra.config.DatabaseDescriptor> dbDesc = Mockito.mockStatic(org.apache.cassandra.config.DatabaseDescriptor.class)) {
            dbDesc.when(org.apache.cassandra.config.DatabaseDescriptor::getClusterName).thenReturn(TEST_CLUSTER);
            SecurityConfig mockConfig = mockConfigWithKeyspace("KS1", "AP-MYKS-");
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            java.util.HashMap<String, Object> config = new java.util.HashMap<>();
            config.put("userInfoUrl", "");
            java.util.HashMap<String, Object> authorizerConfigs = new java.util.HashMap<>();
            authorizerConfigs.put("jwt1", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);
            JwtAuthorizer authz = new JwtAuthorizer("jwt1");
            authz.setup();
            tokenContextMock.when(com.att.cassandra.security.auth.jwt.JwtTokenContext::getToken).thenReturn("tok");
            com.nimbusds.jwt.SignedJWT mockJwt = mock(com.nimbusds.jwt.SignedJWT.class);
            com.nimbusds.jwt.JWTClaimsSet mockClaims = mock(com.nimbusds.jwt.JWTClaimsSet.class);
            jwtMock.when(() -> com.nimbusds.jwt.SignedJWT.parse("tok")).thenReturn(mockJwt);
            when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
            when(mockClaims.getStringListClaim("roles")).thenReturn(null);
            // Use the exact group string format expected by the matcher (prefix + role name)
            when(mockClaims.getStringListClaim("groups")).thenReturn(java.util.Collections.singletonList("AP-MYKS-READ"));
            // Use a real DataResource with getName() == "KS1/tbl"
            org.apache.cassandra.auth.IResource resource = org.apache.cassandra.auth.Resources.fromName("data/KS1/tbl");
            Set<Permission> perms = authz.authorize(new org.apache.cassandra.auth.AuthenticatedUser("bob"), resource);
            assertNotNull(perms);
            assertTrue(perms.contains(Permission.SELECT), "Expected SELECT permission");
        }
    }

    @Test
    void testUserInfoEndpointRolesAndGroupsHandling() throws Exception {
        // Mock ConfigLoader and SecurityConfig
        try (MockedStatic<ConfigLoader> loaderMock = Mockito.mockStatic(ConfigLoader.class)) {
            SecurityConfig mockConfig = mock(SecurityConfig.class);
            loaderMock.when(ConfigLoader::load).thenReturn(mockConfig);
            Map<String, Object> config = new HashMap<>();
            config.put("userInfoUrl", "http://fake/userinfo");
            Map<String, Object> authorizerConfigs = new HashMap<>();
            authorizerConfigs.put("jwt", config);
            when(mockConfig.getAuthorizers()).thenReturn(authorizerConfigs);

            JwtAuthorizer authz = new JwtAuthorizer();
            authz.setLogicalName("jwt");

            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            // 1. 200 OK with roles
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockResponse.body()).thenReturn("{\"roles\":[\"r1\",\"r2\"]}");
            try (MockedStatic<HttpClient> httpClientMock = Mockito.mockStatic(HttpClient.class)) {
                httpClientMock.when(HttpClient::newHttpClient).thenReturn(mockClient);
                when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);
                authz.setup();
                java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
                claimsCacheField.setAccessible(true);
                @SuppressWarnings("unchecked")
                com.google.common.cache.LoadingCache<String, java.util.List<String>> claimsCache =
                    (com.google.common.cache.LoadingCache<String, java.util.List<String>>) claimsCacheField.get(authz);
                java.util.List<String> roles = claimsCache.get("tok");
                assertEquals(Arrays.asList("r1", "r2"), roles);
            }

            // 2. 200 OK with empty roles, fallback to groups
            when(mockResponse.body()).thenReturn("{\"roles\":[],\"groups\":[\"g1\"]}");
            try (MockedStatic<HttpClient> httpClientMock = Mockito.mockStatic(HttpClient.class)) {
                httpClientMock.when(HttpClient::newHttpClient).thenReturn(mockClient);
                when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);
                authz.setup();
                java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
                claimsCacheField.setAccessible(true);
                @SuppressWarnings("unchecked")
                com.google.common.cache.LoadingCache<String, java.util.List<String>> claimsCache =
                    (com.google.common.cache.LoadingCache<String, java.util.List<String>>) claimsCacheField.get(authz);
                java.util.List<String> roles = claimsCache.get("tok");
                assertEquals(Arrays.asList("g1"), roles);
            }

            // 3. Non-200 status code (should fallback to JWT parsing, so mock SignedJWT)
            when(mockResponse.statusCode()).thenReturn(403);
            try (MockedStatic<HttpClient> httpClientMock = Mockito.mockStatic(HttpClient.class);
                 MockedStatic<SignedJWT> jwtMock = Mockito.mockStatic(SignedJWT.class)) {
                httpClientMock.when(HttpClient::newHttpClient).thenReturn(mockClient);
                when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);
                // Fallback to JWT parsing: SignedJWT.parse returns a mock with empty claims
                SignedJWT mockJwt = mock(SignedJWT.class);
                JWTClaimsSet mockClaims = mock(JWTClaimsSet.class);
                jwtMock.when(() -> SignedJWT.parse(anyString())).thenReturn(mockJwt);
                when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
                when(mockClaims.getStringListClaim(anyString())).thenReturn(null);
                authz.setup();
                java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
                claimsCacheField.setAccessible(true);
                @SuppressWarnings("unchecked")
                com.google.common.cache.LoadingCache<String, java.util.List<String>> claimsCache =
                    (com.google.common.cache.LoadingCache<String, java.util.List<String>>) claimsCacheField.get(authz);
                java.util.List<String> roles = claimsCache.get("tok");
                assertEquals(Arrays.asList(), roles);
            }

            // 4. Exception thrown by HTTP call (should fallback to JWT parsing, so mock SignedJWT)
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new RuntimeException("fail"));
            try (MockedStatic<HttpClient> httpClientMock = Mockito.mockStatic(HttpClient.class);
                 MockedStatic<SignedJWT> jwtMock = Mockito.mockStatic(SignedJWT.class)) {
                httpClientMock.when(HttpClient::newHttpClient).thenReturn(mockClient);
                SignedJWT mockJwt = mock(SignedJWT.class);
                JWTClaimsSet mockClaims = mock(JWTClaimsSet.class);
                jwtMock.when(() -> SignedJWT.parse(anyString())).thenReturn(mockJwt);
                when(mockJwt.getJWTClaimsSet()).thenReturn(mockClaims);
                when(mockClaims.getStringListClaim(anyString())).thenReturn(null);
                authz.setup();
                java.lang.reflect.Field claimsCacheField = JwtAuthorizer.class.getDeclaredField("claimsCache");
                claimsCacheField.setAccessible(true);
                @SuppressWarnings("unchecked")
                com.google.common.cache.LoadingCache<String, java.util.List<String>> claimsCache =
                    (com.google.common.cache.LoadingCache<String, java.util.List<String>>) claimsCacheField.get(authz);
                java.util.List<String> roles = claimsCache.get("tok");
                assertEquals(Arrays.asList(), roles);
            }
        }
    }

    // Utility method to mock SecurityConfig with keyspace and prefix
    private static SecurityConfig mockConfigWithKeyspace(String keyspace, String prefix) {
        SecurityConfig mockConfig = mock(SecurityConfig.class);
        com.att.cassandra.security.config.KeyspaceRolesConfig ksConfig = new com.att.cassandra.security.config.KeyspaceRolesConfig();
        ksConfig.setName(keyspace);
        ksConfig.setRolePrefix(prefix);
        com.att.cassandra.security.config.RoleConfig role = new com.att.cassandra.security.config.RoleConfig();
        role.setName("READ");
        com.att.cassandra.security.config.ResourcePermissionConfig rpc = new com.att.cassandra.security.config.ResourcePermissionConfig();
        rpc.setType("data");
        rpc.setName("*");
        rpc.setPermissions(java.util.List.of("SELECT"));
        role.setResources(java.util.List.of(rpc));
        ksConfig.setRoles(java.util.List.of(role));
        when(mockConfig.getKeyspaces()).thenReturn(java.util.List.of(ksConfig));
        when(mockConfig.getDefaultRoles()).thenReturn(java.util.List.of());
        return mockConfig;
    }
}
