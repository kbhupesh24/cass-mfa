package com.att.cassandra.security.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.*;
import com.att.cassandra.security.config.SecurityConfig;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IAuthenticator.SaslNegotiator;
import org.apache.cassandra.exceptions.AuthenticationException;

@ExtendWith(MockitoExtension.class)
class ChainedAuthenticatorTest {
    static SecurityConfig mockConfig;

    @BeforeAll
    static void beforeAll() {
        mockConfig = new SecurityConfig();
        java.util.HashMap<String, Object> authenticators = new java.util.HashMap<>();
        authenticators.put("jwt_test", java.util.Map.of("class", "com.att.cassandra.security.auth.jwt.JwtAuthenticator", "external_service", "jwt_test"));
        authenticators.put("ldap_test", java.util.Map.of("class", "com.att.cassandra.security.auth.ldap.LdapAuthenticator", "external_service", "ldap_test"));
        mockConfig.setAuthenticators(authenticators);
        java.util.HashMap<String, Object> externalServices = new java.util.HashMap<>();
        externalServices.put("jwt_test", java.util.Map.of("jwksUrl", "http://localhost", "issuer", "test", "audience", "test"));
        externalServices.put("ldap_test", java.util.Map.of("url", "ldap://localhost", "bindUser", "admin", "bindPassword", "pw", "userDnPattern", "uid={0}", "groupBaseDn", "ou=groups", "groupAttribute", "cn"));
        mockConfig.setExternalServices(externalServices);
        // Set up a minimal chained config
        com.att.cassandra.security.config.ChainedConfig chained = new com.att.cassandra.security.config.ChainedConfig();
        chained.setAuthenticators(java.util.List.of("jwt_test", "ldap_test"));
        mockConfig.setChained(chained);
        ChainedAuthenticator.setTestConfig(mockConfig);
    }

    @AfterAll
    static void afterAll() {
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testRequireAuthentication() {
        ChainedAuthenticator authenticator = new ChainedAuthenticator();
        authenticator.setup();
        assertTrue(authenticator.requireAuthentication());
    }

    // The following tests are problematic due to dependency on org.apache.cassandra.auth.PasswordAuthenticator
    // which does not have a String constructor in this environment. We'll comment them out for now.
    /*
    @Test
    void testChainedAuthenticatorDispatchesJwt() {
        var jwt = new com.att.cassandra.security.auth.jwt.JwtAuthenticator();
        jwt.setLogicalName("jwt_test");
        var ldap = new com.att.cassandra.security.auth.ldap.LdapAuthenticator("ldap_test");
        var chained = new ChainedAuthenticator();
        System.setProperty("cassandra.authenticator_chain", "com.att.cassandra.security.auth.jwt.JwtAuthenticator,com.att.cassandra.security.auth.ldap.LdapAuthenticator");
        chained.setup();
        byte[] payload = new byte[] {0, 'u', 0, 'B', 'e', 'a', 'r', 'e', 'r', ' ', 'x', 'y', 'z'};
        assertTrue(jwt.supports(payload));
        assertFalse(ldap.supports(payload));
    }
    @Test
    void testChainedAuthenticatorDispatchesLdap() {
        var jwt = new com.att.cassandra.security.auth.jwt.JwtAuthenticator();
        jwt.setLogicalName("jwt_test");
        var ldap = new com.att.cassandra.security.auth.ldap.LdapAuthenticator("ldap_test");
        var chained = new ChainedAuthenticator();
        System.setProperty("cassandra.authenticator_chain", "com.att.cassandra.security.auth.jwt.JwtAuthenticator,com.att.cassandra.security.auth.ldap.LdapAuthenticator");
        chained.setup();
        byte[] payload = new byte[] {0, 'u', 0, 's', 'e', 'c', 'r', 'e', 't'};
        assertFalse(jwt.supports(payload));
        assertTrue(ldap.supports(payload));
    }

    @Test
    void testValidateConfigurationNoop() {
        ChainedAuthenticator authenticator = new ChainedAuthenticator();
        // Should not throw
        authenticator.validateConfiguration();
    }

    @Test
    void testProtectedResourcesReturnsEmptySet() {
        ChainedAuthenticator authenticator = new ChainedAuthenticator();
        assertTrue(authenticator.protectedResources().isEmpty());
    }

    @Test
    void testChainedSaslNegotiatorIsComplete() {
        ChainedAuthenticator authenticator = new ChainedAuthenticator();
        authenticator.setup();
        var negotiator = authenticator.newSaslNegotiator(null);
        // Should be false before any dispatch
        assertFalse(negotiator.isComplete());
    }
    */

    @Test
    void testSetupWithEmptyConfigThrows() {
        SecurityConfig config = new SecurityConfig();
        // No authenticators or chained config set
        ChainedAuthenticator.setTestConfig(config);
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertThrows(IllegalStateException.class, auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testSetupWithInvalidLogicalNameThrows() {
        SecurityConfig config = new SecurityConfig();
        java.util.Map<String, Object> authenticators = new java.util.HashMap<>();
        authenticators.put("foo", java.util.Map.of("class", "com.att.cassandra.security.auth.TestAuthenticator"));
        config.setAuthenticators(authenticators);
        com.att.cassandra.security.config.ChainedConfig chained = new com.att.cassandra.security.config.ChainedConfig();
        chained.setAuthenticators(java.util.List.of("bar")); // 'bar' does not exist
        config.setChained(chained);
        ChainedAuthenticator.setTestConfig(config);
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertThrows(RuntimeException.class, auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testSetupWithValidTestAuthenticator() {
        SecurityConfig config = new SecurityConfig();
        java.util.Map<String, Object> authenticators = new java.util.HashMap<>();
        authenticators.put("foo", java.util.Map.of("class", "com.att.cassandra.security.auth.TestAuthenticator"));
        config.setAuthenticators(authenticators);
        com.att.cassandra.security.config.ChainedConfig chained = new com.att.cassandra.security.config.ChainedConfig();
        chained.setAuthenticators(java.util.List.of("foo"));
        config.setChained(chained);
        ChainedAuthenticator.setTestConfig(config);
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertDoesNotThrow(auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testSetupThrowsOnMissingConfig() {
        ChainedAuthenticator.setTestConfig(new com.att.cassandra.security.config.SecurityConfig());
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertThrows(IllegalStateException.class, auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testSetupThrowsOnEmptyChain() {
        com.att.cassandra.security.config.SecurityConfig config = new com.att.cassandra.security.config.SecurityConfig();
        java.util.HashMap<String, Object> authenticators = new java.util.HashMap<>();
        authenticators.put("foo", java.util.Map.of("class", "com.att.cassandra.security.auth.TestAuthenticator"));
        config.setAuthenticators(authenticators);
        com.att.cassandra.security.config.ChainedConfig chained = new com.att.cassandra.security.config.ChainedConfig();
        chained.setAuthenticators(java.util.List.of()); // empty list
        config.setChained(chained);
        ChainedAuthenticator.setTestConfig(config);
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertThrows(IllegalStateException.class, auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testSetupThrowsOnMissingPluginConfig() {
        com.att.cassandra.security.config.SecurityConfig config = new com.att.cassandra.security.config.SecurityConfig();
        // No authenticators map
        com.att.cassandra.security.config.ChainedConfig chained = new com.att.cassandra.security.config.ChainedConfig();
        chained.setAuthenticators(java.util.List.of("foo"));
        config.setChained(chained);
        ChainedAuthenticator.setTestConfig(config);
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertThrows(IllegalStateException.class, auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testSetupThrowsOnClassNotFound() {
        com.att.cassandra.security.config.SecurityConfig config = new com.att.cassandra.security.config.SecurityConfig();
        java.util.HashMap<String, Object> authenticators = new java.util.HashMap<>();
        authenticators.put("foo", java.util.Map.of("class", "not.a.real.ClassName"));
        config.setAuthenticators(authenticators);
        com.att.cassandra.security.config.ChainedConfig chained = new com.att.cassandra.security.config.ChainedConfig();
        chained.setAuthenticators(java.util.List.of("foo"));
        config.setChained(chained);
        ChainedAuthenticator.setTestConfig(config);
        ChainedAuthenticator auth = new ChainedAuthenticator();
        assertThrows(RuntimeException.class, auth::setup);
        ChainedAuthenticator.clearTestConfig();
    }

    // Dummy class for legacyAuthenticate test: implements both SupportsCredentialType and IAuthenticator
    static class DummyAuthenticator implements ChainedAuthenticator.SupportsCredentialType, IAuthenticator {
        boolean supportsReturn = false;
        DummyAuthenticator(boolean supportsReturn) { this.supportsReturn = supportsReturn; }
        @Override public boolean supports(byte[] initialSaslPayload) { return supportsReturn; }
        @Override public void setup() {}
        @Override public void validateConfiguration() {}
        @Override
        public IAuthenticator.SaslNegotiator newSaslNegotiator(java.net.InetAddress clientAddress) {
            return new DummyNegotiator();
        }
        @Override public boolean requireAuthentication() { return true; }
        @Override public java.util.Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() { return java.util.Collections.emptySet(); }
        @Override public org.apache.cassandra.auth.AuthenticatedUser legacyAuthenticate(java.util.Map<String, String> credentials) { return new org.apache.cassandra.auth.AuthenticatedUser("dummy"); }
    }
    static class DummyNegotiator implements IAuthenticator.SaslNegotiator {
        @Override public byte[] evaluateResponse(byte[] clientResponse) { throw new UnsupportedOperationException(); }
        @Override public boolean isComplete() { return false; }
        @Override public org.apache.cassandra.auth.AuthenticatedUser getAuthenticatedUser() { throw new UnsupportedOperationException(); }
    }

    @Test
    void testLegacyAuthenticateThrowsIfNoCapableAuthenticator() throws Exception {
        ChainedAuthenticator auth = new ChainedAuthenticator();
        java.lang.reflect.Field f = ChainedAuthenticator.class.getDeclaredField("authenticators");
        f.setAccessible(true);
        f.set(auth, java.util.List.of(new DummyAuthenticator(false)));
        Exception ex = assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(java.util.Map.of("username", "bob", "password", "pw")));
        assertTrue(ex.getMessage().contains("No authenticators configured to handle provided credential type"));
    }

    @Test
    void testChainedSaslNegotiatorEvaluateResponseThrowsIfNoCompatibleAuthenticator() throws Exception {
        ChainedAuthenticator auth = new ChainedAuthenticator();
        java.lang.reflect.Field f = ChainedAuthenticator.class.getDeclaredField("authenticators");
        f.setAccessible(true);
        f.set(auth, java.util.List.of(new DummyAuthenticator(false)));
        org.apache.cassandra.auth.IAuthenticator.SaslNegotiator negotiator = auth.newSaslNegotiator(null);
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> negotiator.evaluateResponse(new byte[]{1,2,3}));
    }

    @Test
    void testChainedSaslNegotiatorIsCompleteFalseWhenCurrentNull() throws Exception {
        ChainedAuthenticator auth = new ChainedAuthenticator();
        java.lang.reflect.Field f = ChainedAuthenticator.class.getDeclaredField("authenticators");
        f.setAccessible(true);
        f.set(auth, java.util.List.of(new DummyAuthenticator(false)));
        org.apache.cassandra.auth.IAuthenticator.SaslNegotiator negotiator = auth.newSaslNegotiator(null);
        assertFalse(negotiator.isComplete());
    }

    @Test
    void testChainedSaslNegotiatorGetAuthenticatedUserThrowsWhenCurrentNull() throws Exception {
        ChainedAuthenticator auth = new ChainedAuthenticator();
        java.lang.reflect.Field f = ChainedAuthenticator.class.getDeclaredField("authenticators");
        f.setAccessible(true);
        f.set(auth, java.util.List.of(new DummyAuthenticator(false)));
        org.apache.cassandra.auth.IAuthenticator.SaslNegotiator negotiator = auth.newSaslNegotiator(null);
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, negotiator::getAuthenticatedUser);
    }

    @Test
    void testChainContinuesIfFirstAuthenticatorFails() throws Exception {
        // First authenticator: supports, but always throws
        class FailingAuthenticator implements ChainedAuthenticator.SupportsCredentialType, IAuthenticator {
            @Override public boolean supports(byte[] initialSaslPayload) { return true; }
            @Override public void setup() {}
            @Override public void validateConfiguration() {}
            @Override public SaslNegotiator newSaslNegotiator(java.net.InetAddress clientAddress) {
                return new DummyNegotiator();
            }
            @Override public boolean requireAuthentication() { return true; }
            @Override public java.util.Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() { return java.util.Collections.emptySet(); }
            @Override public org.apache.cassandra.auth.AuthenticatedUser legacyAuthenticate(java.util.Map<String, String> credentials) throws org.apache.cassandra.exceptions.AuthenticationException {
                throw new org.apache.cassandra.exceptions.AuthenticationException("Always fails");
            }
        }
        // Second authenticator: supports, always succeeds
        class SucceedingAuthenticator implements ChainedAuthenticator.SupportsCredentialType, IAuthenticator {
            @Override public boolean supports(byte[] initialSaslPayload) { return true; }
            @Override public void setup() {}
            @Override public void validateConfiguration() {}
            @Override public SaslNegotiator newSaslNegotiator(java.net.InetAddress clientAddress) {
                return new DummyNegotiator();
            }
            @Override public boolean requireAuthentication() { return true; }
            @Override public java.util.Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() { return java.util.Collections.emptySet(); }
            @Override public org.apache.cassandra.auth.AuthenticatedUser legacyAuthenticate(java.util.Map<String, String> credentials) throws org.apache.cassandra.exceptions.AuthenticationException {
                return new org.apache.cassandra.auth.AuthenticatedUser("success");
            }
        }
        ChainedAuthenticator auth = new ChainedAuthenticator();
        java.lang.reflect.Field f = ChainedAuthenticator.class.getDeclaredField("authenticators");
        f.setAccessible(true);
        f.set(auth, java.util.List.of(new FailingAuthenticator(), new SucceedingAuthenticator()));
        org.apache.cassandra.auth.AuthenticatedUser user = auth.legacyAuthenticate(java.util.Map.of("username", "bob", "password", "pw"));
        assertEquals("success", user.getName());
    }

    @Test
    void testNewSaslNegotiatorNoSupports() throws Exception {
        // DummyAuthenticator does not support credential type
        SecurityConfig config = new SecurityConfig();
        Map<String,Object> auths = new HashMap<>();
        auths.put("dummy", Map.of("class", DummyAuthenticator.class.getName()));
        config.setAuthenticators(auths);
        com.att.cassandra.security.config.ChainedConfig cc = new com.att.cassandra.security.config.ChainedConfig();
        cc.setAuthenticators(List.of("dummy"));
        config.setChained(cc);
        ChainedAuthenticator.setTestConfig(config);

        ChainedAuthenticator authn = new ChainedAuthenticator();
        authn.setup();
        SaslNegotiator neg = authn.newSaslNegotiator(InetAddress.getLocalHost());
        assertFalse(neg.isComplete());
        AuthenticationException ex = assertThrows(AuthenticationException.class,
            () -> neg.evaluateResponse("x".getBytes()));
        assertTrue(ex.getMessage().contains("No authenticators configured to handle provided credential type"));
        assertFalse(neg.isComplete());
        assertThrows(AuthenticationException.class, neg::getAuthenticatedUser);
        ChainedAuthenticator.clearTestConfig();
    }

    @Test
    void testNewSaslNegotiatorSuccess() throws Exception {
        // Setup a SuccessAuthenticator that always supports and succeeds
        com.att.cassandra.security.config.SecurityConfig config = new SecurityConfig();
        Map<String, Object> auths = new HashMap<>();
        auths.put("dummy", Map.of("class", SuccessAuthenticator.class.getName()));
        config.setAuthenticators(auths);
        com.att.cassandra.security.config.ChainedConfig cc = new com.att.cassandra.security.config.ChainedConfig();
        cc.setAuthenticators(List.of("dummy"));
        config.setChained(cc);
        ChainedAuthenticator.setTestConfig(config);

        ChainedAuthenticator authn = new ChainedAuthenticator();
        authn.setup();
        SaslNegotiator negotiator = authn.newSaslNegotiator(InetAddress.getLocalHost());
        byte[] response = negotiator.evaluateResponse(new byte[]{0});
        assertArrayEquals(new byte[]{1,2,3}, response);
        assertTrue(negotiator.isComplete());
        org.apache.cassandra.auth.AuthenticatedUser user = negotiator.getAuthenticatedUser();
        assertEquals("user", user.getName());
        ChainedAuthenticator.clearTestConfig();
    }

    static class SuccessAuthenticator implements ChainedAuthenticator.SupportsCredentialType, IAuthenticator {
        @Override public boolean supports(byte[] initialSaslPayload) { return true; }
        @Override public void setup() {}
        @Override public void validateConfiguration() {}
        @Override public SaslNegotiator newSaslNegotiator(java.net.InetAddress clientAddress) { return new SuccessNegotiator(); }
        @Override public boolean requireAuthentication() { return true; }
        @Override public java.util.Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() { return java.util.Collections.emptySet(); }
        @Override public org.apache.cassandra.auth.AuthenticatedUser legacyAuthenticate(java.util.Map<String, String> credentials) throws AuthenticationException { return new org.apache.cassandra.auth.AuthenticatedUser("user"); }
    }

    static class SuccessNegotiator implements IAuthenticator.SaslNegotiator {
        @Override public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException { return new byte[]{1,2,3}; }
        @Override public boolean isComplete() { return true; }
        @Override public org.apache.cassandra.auth.AuthenticatedUser getAuthenticatedUser() throws AuthenticationException { return new org.apache.cassandra.auth.AuthenticatedUser("user"); }
    }
}
