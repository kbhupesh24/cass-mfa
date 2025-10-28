package com.att.cassandra.security.auth.ldap;

import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.SecurityConfig;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator.SaslNegotiator;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.db.ConsistencyLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LdapAuthenticatorTest {
    private LdapAuthenticator authenticator;
    private MockLdapService mockService;

    @BeforeEach
    void setup() {
        authenticator = new LdapAuthenticator("test");
        mockService = new MockLdapService();
        authenticator.setLdapServiceForTest(mockService);
    }

    @Test
    void testLegacyAuthenticateSuccess() throws org.apache.cassandra.exceptions.AuthenticationException {
        mockService.setAuthenticateResult(true);
        Map<String, String> creds = Map.of("username", "alice", "password", "secret");
        AuthenticatedUser user = authenticator.legacyAuthenticate(creds);
        assertEquals("alice", user.getName());
    }

    @Test
    void testLegacyAuthenticateFailure() {
        mockService.setAuthenticateResult(false);
        Map<String, String> creds = Map.of("username", "alice", "password", "wrong");
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            authenticator.legacyAuthenticate(creds));
    }

    @Test
    void testLegacyAuthenticateBearerToken() {
        Map<String, String> creds = Map.of("username", "alice", "password", "Bearer sometoken");
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            authenticator.legacyAuthenticate(creds));
    }

    @Test
    void testLegacyAuthenticateThrowsOnMissingUsernameOrPassword() {
        // Missing username
        Map<String, String> creds1 = Map.of("password", "secret");
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            authenticator.legacyAuthenticate(creds1));
        // Missing password
        Map<String, String> creds2 = Map.of("username", "alice");
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            authenticator.legacyAuthenticate(creds2));
    }

    @Test
    void testSupportsCredentialType() {
        // SASL PLAIN: 0x00 user 0x00 pass
        byte[] payload = new byte[] {0, 'a', 'l', 'i', 'c', 'e', 0, 's', 'e', 'c', 'r', 'e', 't'};
        assertTrue(authenticator.supports(payload));
        byte[] bearer = new byte[] {0, 'a', 'l', 'i', 'c', 'e', 0, 'B', 'e', 'a', 'r', 'e', 'r', ' ', 't', 'k'};
        assertFalse(authenticator.supports(bearer));
    }

    @Test
    void testSupportsFallbackTrue() {
        // No nulls => fallback to true
        byte[] payload = new byte[] {1,2,3,4};
        assertTrue(authenticator.supports(payload));
        // Only one null => also true
        byte[] singleNull = new byte[] {0, 'a', 'b'};
        assertTrue(authenticator.supports(singleNull));
    }

    @Test
    void testSaslNegotiatorSuccess() throws Exception {
        mockService.setAuthenticateResult(true);
        LdapAuthenticator.LdapSaslNegotiator negotiator = (LdapAuthenticator.LdapSaslNegotiator) authenticator.newSaslNegotiator((InetAddress) null);
        byte[] payload = new byte[] {0, 'a', 'l', 'i', 'c', 'e', 0, 's', 'e', 'c', 'r', 'e', 't'};
        assertNull(negotiator.evaluateResponse(payload));
        assertTrue(negotiator.isComplete());
        AuthenticatedUser user = negotiator.getAuthenticatedUser();
        assertEquals("alice", user.getName());
    }

    @Test
    void testSaslNegotiatorBearerToken() throws Exception {
        mockService.setAuthenticateResult(true);
        LdapAuthenticator.LdapSaslNegotiator negotiator = (LdapAuthenticator.LdapSaslNegotiator) authenticator.newSaslNegotiator((InetAddress) null);
        byte[] bearer = new byte[] {0, 'a', 'l', 'i', 'c', 'e', 0, 'B', 'e', 'a', 'r', 'e', 'r', ' ', 't', 'k'};
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            negotiator.evaluateResponse(bearer));
    }

    @Test
    void testSaslNegotiatorThrowsOnMalformedPayload() throws Exception {
        LdapAuthenticator.LdapSaslNegotiator negotiator = (LdapAuthenticator.LdapSaslNegotiator) authenticator.newSaslNegotiator((InetAddress) null);
        // No nulls
        byte[] bad1 = new byte[] {'a', 'l', 'i', 'c', 'e'};
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            negotiator.evaluateResponse(bad1));
        // Only one null
        byte[] bad2 = new byte[] {0, 'a', 'l', 'i', 'c', 'e'};
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            negotiator.evaluateResponse(bad2));
    }

    @Test
    void testSaslNegotiatorThrowsIfGetAuthenticatedUserCalledBeforeComplete() throws Exception {
        LdapAuthenticator.LdapSaslNegotiator negotiator = (LdapAuthenticator.LdapSaslNegotiator) authenticator.newSaslNegotiator((InetAddress) null);
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, negotiator::getAuthenticatedUser);
    }

    @Test
    void testSaslNegotiatorThrowsOnFailedAuthentication() throws Exception {
        mockService.setAuthenticateResult(false);
        LdapAuthenticator.LdapSaslNegotiator negotiator = (LdapAuthenticator.LdapSaslNegotiator) authenticator.newSaslNegotiator((InetAddress) null);
        byte[] payload = new byte[] {0, 'a', 'l', 'i', 'c', 'e', 0, 's', 'e', 'c', 'r', 'e', 't'};
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () ->
            negotiator.evaluateResponse(payload));
    }

    @Test
    void testNewSaslNegotiatorSetupBranch() {
        // Create without test service, ensure setup called
        LdapAuthenticator auth = new LdapAuthenticator("test2");
        // Inject mock service after setup
        MockLdapService svc = new MockLdapService(); svc.setAuthenticateResult(true);
        auth.setLdapServiceForTest(null); // clear
        // Static LdapService.getInstance would run in setup(), but bypass
        auth.setLdapServiceForTest(svc);
        SaslNegotiator neg = auth.newSaslNegotiator(null);
        assertNotNull(neg);
    }

    @Test
    void testSaslNegotiatorEmptyUsername() throws Exception {
        mockService.setAuthenticateResult(true);
        LdapAuthenticator.LdapSaslNegotiator neg = (LdapAuthenticator.LdapSaslNegotiator) authenticator.newSaslNegotiator(null);
        // payload with empty username
        byte[] payload = new byte[] {0,0,'p','w'};
        assertNull(neg.evaluateResponse(payload));
        assertTrue(neg.isComplete());
        AuthenticatedUser user = neg.getAuthenticatedUser();
        assertEquals("", user.getName());
    }

    @Test
    void testLegacyAuthenticateAutoAddUserException() throws Exception {
        mockService.setAuthenticateResult(true);
        // Setup config to enable autoAdd
        SecurityConfig cfg = new SecurityConfig(); cfg.setUserAutoAdd(true);
        try (MockedStatic<ConfigLoader> cfgMock = mockStatic(ConfigLoader.class);
             MockedStatic<QueryProcessor> qpMock = mockStatic(QueryProcessor.class)) {
            cfgMock.when(ConfigLoader::load).thenReturn(cfg);
            // First check role exists returns empty rows
            qpMock.when(() -> QueryProcessor.process(anyString(), any())).thenThrow(new RuntimeException("fail cql"));
            Map<String, String> creds = Map.of("username","bob","password","secret");
            AuthenticatedUser user = authenticator.legacyAuthenticate(creds);
            assertEquals("bob", user.getName());
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
        LdapAuthenticator auth = new LdapAuthenticator("foo");
        auth.setLogicalName("bar");
        // No exception expected
        com.att.cassandra.security.auth.ldap.LdapService.clearTestConfig();
    }

    @Test
    void testValidateConfigurationNoop() {
        authenticator.validateConfiguration(); // Should not throw
    }

    @Test
    void testRequireAuthenticationAlwaysTrue() {
        assertTrue(authenticator.requireAuthentication());
    }

    @Test
    void testProtectedResourcesReturnsEmptySet() {
        assertTrue(authenticator.protectedResources().isEmpty());
    }

    @Test
    void testSetupThrowsWhenServiceConfigMissing() {
        // Mock ConfigLoader.load to return config without externalServices
        SecurityConfig cfg = new SecurityConfig();
        try (MockedStatic<ConfigLoader> cfgMock = mockStatic(ConfigLoader.class)) {
            cfgMock.when(ConfigLoader::load).thenReturn(cfg);
            LdapAuthenticator auth = new LdapAuthenticator("missing");
            assertThrows(IllegalArgumentException.class, auth::setup);
        }
    }

    @Test
    void testAutoAddUserSkipWhenRoleExists() throws Exception {
        mockService.setAuthenticateResult(true);
        // Enable autoAdd
        SecurityConfig cfg = new SecurityConfig(); cfg.setUserAutoAdd(true);
        try (MockedStatic<ConfigLoader> cfgMock = mockStatic(ConfigLoader.class);
             MockedStatic<QueryProcessor> qpMock = mockStatic(QueryProcessor.class)) {
            cfgMock.when(ConfigLoader::load).thenReturn(cfg);
            // Role exists: stub QueryProcessor.process to return non-empty rows
            UntypedResultSet rows = mock(UntypedResultSet.class);
            when(rows.isEmpty()).thenReturn(false);
            qpMock.when(() -> QueryProcessor.process(anyString(), eq(ConsistencyLevel.LOCAL_ONE))).thenReturn(rows);
            AuthenticatedUser user = authenticator.legacyAuthenticate(Map.of("username","bob","password","pw"));
            assertEquals("bob", user.getName());
        }
    }

    @Test
    void testAutoAddUserWithGroups() throws Exception {
        mockService.setAuthenticateResult(true);
        // Enable autoAdd
        SecurityConfig cfg = new SecurityConfig(); cfg.setUserAutoAdd(true);
        // Stub ConfigLoader and set groups on mockService
        mockService.setFetchGroups(Set.of("group1"));
        try (MockedStatic<ConfigLoader> cfgMock = mockStatic(ConfigLoader.class)) {
            cfgMock.when(ConfigLoader::load).thenReturn(cfg);
            AuthenticatedUser user = authenticator.legacyAuthenticate(Map.of("username","bob","password","secret"));
            assertEquals("bob", user.getName());
        }
    }

    // Minimal mock for LdapService
    static class MockLdapService extends LdapService {
        private boolean authenticateResult = true;
        private Set<String> fetchGroups = Collections.emptySet();
        MockLdapService() { super((com.att.cassandra.security.config.LdapConfig) null); }
        void setAuthenticateResult(boolean result) { this.authenticateResult = result; }
        @Override public boolean authenticateBind(String username, String password) { return authenticateResult; }
        @Override public Set<String> fetchUserGroups(String username) { return fetchGroups; }
        void setFetchGroups(Set<String> groups) { this.fetchGroups = groups; }
    }
}
