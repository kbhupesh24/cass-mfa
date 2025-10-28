package com.att.cassandra.security.auth.jwt;

import com.att.cassandra.security.config.SecurityConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator.SaslNegotiator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import org.mockito.MockedStatic;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import java.nio.charset.StandardCharsets;

class JwtAuthenticatorTest {
    static class TestJwtAuthenticator extends JwtAuthenticator {
        @Override
        protected AuthenticatedUser newAuthenticatedUser(String username) {
            return new AuthenticatedUser(username) {
                @Override public java.util.Set<org.apache.cassandra.auth.RoleResource> getRoles() { return java.util.Collections.emptySet(); }
            };
        }
    }


    @Test
    void testSetLogicalNameAndRequireAuthentication() {
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        assertTrue(auth.requireAuthentication());
    }


    @Test
    void testLegacyAuthenticateThrowsOnNonBearer() {
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        java.util.Map<String, String> creds = java.util.Map.of("username", "bob", "password", "notbearer");
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
    }


    @Test
    void testLegacyAuthenticateThrowsOnNullPassword() {
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        java.util.Map<String, String> creds = java.util.Map.of("username", "bob");
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
    }


    @Test
    void testProtectedResourcesAndSaslNegotiator() {
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        assertNotNull(auth.protectedResources());
        assertNotNull(auth.newSaslNegotiator(null));
    }


    @Test
    void testValidateConfigurationCoversNoop() {
        JwtAuthenticator auth = new JwtAuthenticator();
        // Should not throw
        auth.validateConfiguration();
    }


    @Test
    void testSetupThrowsOnMissingRequiredFields() {
        JwtAuthenticator auth = new JwtAuthenticator("foo");
        java.util.Map<String, Object> config = new java.util.HashMap<>();
        try (org.mockito.MockedStatic<com.att.cassandra.security.config.SecurityConfig> configMock = org.mockito.Mockito.mockStatic(com.att.cassandra.security.config.SecurityConfig.class)) {
            configMock.when(() -> com.att.cassandra.security.config.SecurityConfig.getExternalServiceConfig("foo")).thenReturn(config);
            Exception ex = assertThrows(IllegalStateException.class, auth::setup);
            assertTrue(ex.getMessage().contains("Missing required JWT config"));
        }
    }


    @Test
    void testSetupSuccess() {
        JwtAuthenticator auth = new JwtAuthenticator("jwt_test");
        Map<String, Object> cfg = Map.of(
            "jwksUrl", "http://localhost/jwks",
            "issuer", "my-issuer",
            "audience", "my-audience"
        );
        try (MockedStatic<SecurityConfig> sc = mockStatic(SecurityConfig.class)) {
            sc.when(() -> SecurityConfig.getExternalServiceConfig("jwt_test")).thenReturn(cfg);
            assertDoesNotThrow(auth::setup);
            // verify fields via reflection
            java.lang.reflect.Field fUrl = JwtAuthenticator.class.getDeclaredField("jwksUrl");
            java.lang.reflect.Field fIss = JwtAuthenticator.class.getDeclaredField("issuer");
            java.lang.reflect.Field fAud = JwtAuthenticator.class.getDeclaredField("audience");
            fUrl.setAccessible(true); fIss.setAccessible(true); fAud.setAccessible(true);
            assertEquals("http://localhost/jwks", fUrl.get(auth));
            assertEquals("my-issuer", fIss.get(auth));
            assertEquals("my-audience", fAud.get(auth));
        } catch (Exception e) {
            fail("Reflection error: " + e.getMessage());
        }
    }

    @Test
    void testLegacyAuthenticateHappyPathAndFailures() throws Exception {
        JwtAuthenticator auth = new JwtAuthenticator();
        java.lang.reflect.Field f1 = JwtAuthenticator.class.getDeclaredField("jwksUrl");
        java.lang.reflect.Field f2 = JwtAuthenticator.class.getDeclaredField("issuer");
        java.lang.reflect.Field f3 = JwtAuthenticator.class.getDeclaredField("audience");
        f1.setAccessible(true); f2.setAccessible(true); f3.setAccessible(true);
        f1.set(auth, "http://localhost/jwks");
        f2.set(auth, "iss");
        f3.set(auth, "aud");
        java.util.Map<String, String> creds = new java.util.HashMap<>();
        creds.put("password", "Bearer tok");
        com.nimbusds.jwt.SignedJWT jwt = mock(com.nimbusds.jwt.SignedJWT.class);
        com.nimbusds.jose.jwk.JWKSet jwkSet = mock(com.nimbusds.jose.jwk.JWKSet.class);
        com.nimbusds.jose.jwk.JWK jwk = mock(com.nimbusds.jose.jwk.JWK.class);
        com.nimbusds.jose.JWSHeader header = mock(com.nimbusds.jose.JWSHeader.class);
        when(jwt.getHeader()).thenReturn(header);
        when(header.getKeyID()).thenReturn("kid");
        when(jwkSet.getKeyByKeyId("kid")).thenReturn(jwk);
        // Generate real RSA key for verification
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();
        com.nimbusds.jose.jwk.RSAKey rsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder((java.security.interfaces.RSAPublicKey) kp.getPublic())
                .build();
        when(jwk.toRSAKey()).thenReturn(rsaKey);
        // Stub signature and claims
        when(jwt.verify(any(com.nimbusds.jose.JWSVerifier.class))).thenReturn(true);
        com.nimbusds.jwt.JWTClaimsSet claims = mock(com.nimbusds.jwt.JWTClaimsSet.class);
        when(jwt.getJWTClaimsSet()).thenReturn(claims);
        when(claims.getIssuer()).thenReturn("iss");
        when(claims.getAudience()).thenReturn(java.util.Collections.singletonList("aud"));
        when(claims.getSubject()).thenReturn("bob");
        try (MockedStatic<SignedJWT> jwtMock = mockStatic(SignedJWT.class);
             MockedStatic<JWKSet> jwkSetMock = mockStatic(JWKSet.class)) {
            jwtMock.when(() -> SignedJWT.parse("tok")).thenReturn(jwt);
            jwkSetMock.when(() -> JWKSet.load(new java.net.URL("http://localhost/jwks"))).thenReturn(jwkSet);
            // Happy path
            org.apache.cassandra.auth.AuthenticatedUser user = auth.legacyAuthenticate(creds);
            assertEquals("bob", user.getName());
            // JWK not found
            when(jwkSet.getKeyByKeyId("kid")).thenReturn(null);
            assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
            // Signature fail
            when(jwkSet.getKeyByKeyId("kid")).thenReturn(jwk);
            when(jwt.verify(any(com.nimbusds.jose.JWSVerifier.class))).thenReturn(false);
            assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
            // Issuer fail
            when(jwt.verify(any(com.nimbusds.jose.JWSVerifier.class))).thenReturn(true);
            when(claims.getIssuer()).thenReturn("wrong");
            assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
            // Audience fail
            when(claims.getIssuer()).thenReturn("iss");
            when(claims.getAudience()).thenReturn(java.util.Collections.emptyList());
            assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
            // No subject
            when(claims.getAudience()).thenReturn(java.util.Collections.singletonList("aud"));
            when(claims.getSubject()).thenReturn(null);
            assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
        }
    }

    @Test
    void testJwtSaslNegotiatorHappyPath() throws Exception {
        // Use TestJwtAuthenticator to override user creation
        TestJwtAuthenticator auth = new TestJwtAuthenticator();
        auth.setLogicalName("jwt_test");
        // Set private fields via reflection
        java.lang.reflect.Field f1 = JwtAuthenticator.class.getDeclaredField("jwksUrl");
        java.lang.reflect.Field f2 = JwtAuthenticator.class.getDeclaredField("issuer");
        java.lang.reflect.Field f3 = JwtAuthenticator.class.getDeclaredField("audience");
        f1.setAccessible(true); f2.setAccessible(true); f3.setAccessible(true);
        f1.set(auth, "http://dummy/jwks");
        f2.set(auth, "iss");
        f3.set(auth, "aud");

        var negotiator = auth.newSaslNegotiator(null);

        // Generate RSA keypair and JWK with kid "test-kid"
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();
        java.security.interfaces.RSAPublicKey pub = (java.security.interfaces.RSAPublicKey) kp.getPublic();
        java.security.interfaces.RSAPrivateKey priv = (java.security.interfaces.RSAPrivateKey) kp.getPrivate();
        String kid = "test-kid";
        com.nimbusds.jose.jwk.RSAKey jwk = new com.nimbusds.jose.jwk.RSAKey.Builder(pub)
                .keyID(kid)
                .build();
        com.nimbusds.jose.jwk.JWKSet jwkSetObj = new com.nimbusds.jose.jwk.JWKSet(jwk);

        // Stub JWKSet.load to return our JWKSet
        try (org.mockito.MockedStatic<com.nimbusds.jose.jwk.JWKSet> jwkMock = mockStatic(com.nimbusds.jose.jwk.JWKSet.class)) {
            jwkMock.when(() -> com.nimbusds.jose.jwk.JWKSet.load(any(java.net.URL.class)))
                   .thenReturn(jwkSetObj);

            // Create signed JWT
            com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .keyID(kid)
                    .build();
            com.nimbusds.jwt.JWTClaimsSet claimsSet = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                    .issuer("iss")
                    .audience("aud")
                    .subject("bob")
                    .expirationTime(new java.util.Date(new java.util.Date().getTime() + 60_000))
                    .build();
            com.nimbusds.jwt.SignedJWT signedJWT = new com.nimbusds.jwt.SignedJWT(header, claimsSet);
            signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(priv));
            String token = signedJWT.serialize();

            // Build SASL PLAIN payload: authzid=empty, authcid="u", password="Bearer <token>"
            String payloadStr = "\u0000u\u0000Bearer " + token;
            byte[] payload = payloadStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            negotiator.evaluateResponse(payload);
            org.apache.cassandra.auth.AuthenticatedUser user = negotiator.getAuthenticatedUser();
            assertEquals("bob", user.getName());
        }
    }


    @Test
    void testJwtSaslNegotiatorInvalidSaslPayload() {
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        var negotiator = auth.newSaslNegotiator(null);

        // Invalid SASL payload
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> negotiator.evaluateResponse(new byte[] {0, 'u', 's', 'e', 'r'}));
    }


    @Test
    void testJwtSaslNegotiatorInvalidBearerToken() throws Exception {
        JwtAuthenticator auth = new JwtAuthenticator();
        java.lang.reflect.Field f1 = JwtAuthenticator.class.getDeclaredField("jwksUrl");
        java.lang.reflect.Field f2 = JwtAuthenticator.class.getDeclaredField("issuer");
        java.lang.reflect.Field f3 = JwtAuthenticator.class.getDeclaredField("audience");
        f1.setAccessible(true); f2.setAccessible(true); f3.setAccessible(true);
        f1.set(auth, "http://localhost/jwks");
        f2.set(auth, "iss");
        f3.set(auth, "aud");

        var negotiator = auth.newSaslNegotiator(null);

        // Invalid SASL payload
        assertThrows(org.apache.cassandra.exceptions.AuthenticationException.class, () -> negotiator.evaluateResponse(new byte[] {0, 'u', 's', 'e', 'r'}));
    }

    @Test
    void testLegacyAuthenticateParseException() throws Exception {
        JwtAuthenticator auth = new JwtAuthenticator();
        java.util.Map<String, String> creds = Map.of("password", "Bearer badtoken");
        // Mock SignedJWT.parse to throw ParseException
        try (MockedStatic<SignedJWT> jwtMock = mockStatic(SignedJWT.class)) {
            jwtMock.when(() -> SignedJWT.parse("badtoken")).thenThrow(new ParseException("bad", 0));
            AuthenticationException ex = assertThrows(AuthenticationException.class, () -> auth.legacyAuthenticate(creds));
            assertTrue(ex.getMessage().contains("JWT authentication failed"));
        }
    }

    @Test
    void testJwtSaslNegotiatorParseException() throws Exception {
        // Setup authenticator with valid JWT config
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        // Set private config fields
        java.lang.reflect.Field f1 = JwtAuthenticator.class.getDeclaredField("jwksUrl");
        java.lang.reflect.Field f2 = JwtAuthenticator.class.getDeclaredField("issuer");
        java.lang.reflect.Field f3 = JwtAuthenticator.class.getDeclaredField("audience");
        f1.setAccessible(true); f2.setAccessible(true); f3.setAccessible(true);
        f1.set(auth, "http://localhost/jwks");
        f2.set(auth, "iss");
        f3.set(auth, "aud");

        SaslNegotiator neg = auth.newSaslNegotiator(null);
        // Build proper SASL PLAIN payload for Bearer
        String payloadStr = "\u0000u\u0000Bearer token123";
        byte[] payload = payloadStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // Mock SignedJWT.parse to throw ParseException
        try (MockedStatic<SignedJWT> jwtMock = mockStatic(SignedJWT.class)) {
            jwtMock.when(() -> SignedJWT.parse("token123")).thenThrow(new ParseException("bad format", 0));
            AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> neg.evaluateResponse(payload));
            assertTrue(ex.getMessage().contains("JWT authentication failed"));
        }
    }

    @Test
    void testJwtSaslNegotiatorJoseException() throws Exception {
        JwtAuthenticator auth = new JwtAuthenticator();
        auth.setLogicalName("jwt_test");
        java.lang.reflect.Field f1 = JwtAuthenticator.class.getDeclaredField("jwksUrl");
        java.lang.reflect.Field f2 = JwtAuthenticator.class.getDeclaredField("issuer");
        java.lang.reflect.Field f3 = JwtAuthenticator.class.getDeclaredField("audience");
        f1.setAccessible(true); f2.setAccessible(true); f3.setAccessible(true);
        f1.set(auth, "http://localhost/jwks");
        f2.set(auth, "iss");
        f3.set(auth, "aud");

        SaslNegotiator neg = auth.newSaslNegotiator(null);
        String payloadStr = "\u0000u\u0000Bearer tokenABC";
        byte[] payload = payloadStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // Mock SignedJWT.parse succeeds, then jwt.verify throws JOSEException
        // Prepare stubs
        SignedJWT jwtStub = mock(SignedJWT.class);
        JWK jwkStub = mock(JWK.class);
        RSAKey rsaKeyStub = mock(RSAKey.class);
        when(jwkStub.toRSAKey()).thenReturn(rsaKeyStub);
        JWKSet jwkSetStub = mock(JWKSet.class);
        when(jwkSetStub.getKeyByKeyId(any())).thenReturn(jwkStub);
        // Mock static methods and jwt behavior
        try (MockedStatic<SignedJWT> jwtMock = mockStatic(SignedJWT.class);
             MockedStatic<JWKSet> jwkMock = mockStatic(JWKSet.class)) {
            jwtMock.when(() -> SignedJWT.parse("tokenABC")).thenReturn(jwtStub);
            jwkMock.when(() -> JWKSet.load(any(URL.class))).thenReturn(jwkSetStub);
            // Header and verify behavior
            JWSHeader headerStub = mock(JWSHeader.class);
            when(jwtStub.getHeader()).thenReturn(headerStub);
            when(headerStub.getKeyID()).thenReturn("kid");
            when(jwtStub.verify(any(RSASSAVerifier.class))).thenThrow(new JOSEException("jose err"));
            AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> neg.evaluateResponse(payload));
            assertTrue(ex.getMessage().contains("JWT authentication failed")
                       || ex.getMessage().contains("unexpected error"));
        }
    }

    @Test
    void testSetUserFactoryAndCreateUser() {
        JwtAuthenticator auth = new JwtAuthenticator();
        AtomicBoolean called = new AtomicBoolean(false);
        auth.setUserFactory(username -> {
            called.set(true);
            return new AuthenticatedUser(username);
        });
        AuthenticatedUser user = auth.createUser("alice");
        assertTrue(called.get());
        assertEquals("alice", user.getName());
    }

    @Test
    void testSupportsValidAndInvalidPayloads() {
        JwtAuthenticator auth = new JwtAuthenticator();
        // valid payload: [0, 'u',0,'B',...] => supports true
        String valid = "\u0000u\u0000Bearer tok";
        assertTrue(auth.supports(valid.getBytes(StandardCharsets.UTF_8)));
        // invalid payload: missing second null
        byte[] invalid = new byte[] {0, 'u', 'x', 'y'};
        assertFalse(auth.supports(invalid));
    }

    @Test
    void testJwtSaslNegotiatorUnexpectedError() throws Exception {
        JwtAuthenticator auth = new JwtAuthenticator();
        // set config fields
        java.lang.reflect.Field f1 = JwtAuthenticator.class.getDeclaredField("jwksUrl");
        java.lang.reflect.Field f2 = JwtAuthenticator.class.getDeclaredField("issuer");
        java.lang.reflect.Field f3 = JwtAuthenticator.class.getDeclaredField("audience");
        f1.setAccessible(true); f2.setAccessible(true); f3.setAccessible(true);
        f1.set(auth, "http://localhost/jwks");
        f2.set(auth, "iss");
        f3.set(auth, "aud");
        SaslNegotiator neg = auth.newSaslNegotiator(null);
        String payloadStr = "\u0000u\u0000Bearer tokenX";
        byte[] payload = payloadStr.getBytes(StandardCharsets.UTF_8);
        try (MockedStatic<SignedJWT> jwtMock = mockStatic(SignedJWT.class)) {
            jwtMock.when(() -> SignedJWT.parse("tokenX")).thenThrow(new RuntimeException("boom"));
            AuthenticationException ex = assertThrows(AuthenticationException.class,
                () -> neg.evaluateResponse(payload));
            assertTrue(ex.getMessage().contains("unexpected error"));
        }
    }

    @Test
    void testJwtSaslNegotiatorInvalidPayload() {
        JwtAuthenticator auth = new JwtAuthenticator();
        SaslNegotiator neg = auth.newSaslNegotiator(null);
        byte[] bad = new byte[] {1,2,3};
        AuthenticationException ex = assertThrows(AuthenticationException.class,
            () -> neg.evaluateResponse(bad));
        assertTrue(ex.getMessage().contains("Invalid SASL PLAIN payload for JWT"));
    }

}
