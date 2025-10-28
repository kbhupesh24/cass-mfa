package com.att.cassandra.security.auth.jwt;

import com.att.cassandra.security.auth.ChainedAuthenticator;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.cassandra.auth.*;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class JwtAuthenticator implements IAuthenticator, ChainedAuthenticator.SupportsCredentialType {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticator.class);

    private String logicalName;
    private String jwksUrl;
    private String issuer;
    private String audience;
    private final Duration clockSkew = Duration.ofSeconds(30);

    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private LoadingCache<String, List<String>> claimsCache;

    public JwtAuthenticator() {}

    public JwtAuthenticator(String logicalName) {
        this.logicalName = logicalName;
    }

    public void setLogicalName(String logicalName) {
        this.logicalName = logicalName;
    }

    @Override
    public boolean supports(byte[] initialSaslPayload) {
        int firstNull = -1, secondNull = -1;
        for (int i = 0; i < initialSaslPayload.length; i++) {
            if (initialSaslPayload[i] == 0) {
                if (firstNull == -1) {
                    firstNull = i;
                } else if (secondNull == -1) {
                    secondNull = i;
                    break;
                }
            }
        }

        if (firstNull >= 0 && secondNull >= 0 && secondNull >= firstNull + 1) {
            String password = new String(initialSaslPayload, secondNull + 1,
                    initialSaslPayload.length - (secondNull + 1), StandardCharsets.UTF_8);
            return password.startsWith("Bearer ");
        }
        return false;
    }

    @Override
    public void validateConfiguration() throws ConfigurationException {
    }

    @Override
    public void setup() {
        logger.info("Setting up JwtAuthenticator with logicalName: {}", logicalName);

        // Load config for this logicalName from external_services in SecurityConfig
        Map<String, Object> jwtConfig = com.att.cassandra.security.config.SecurityConfig
                .getExternalServiceConfig(logicalName);

        if (jwtConfig == null) {
            throw new IllegalArgumentException("No external_service config found for logicalName: " + logicalName);
        }

        this.jwksUrl = (String) jwtConfig.get("jwksUrl");
        this.issuer = (String) jwtConfig.get("issuer");
        this.audience = (String) jwtConfig.get("audience");

        if (jwksUrl == null || issuer == null) {
            throw new IllegalStateException("Missing required JWT config (jwksUrl, issuer) for logicalName: " + logicalName);
        }

        logger.info("JWT Config - jwksUrl: {}, issuer: {}, audience: {}", jwksUrl, issuer, audience);

        // Initialize JWT processor
        try {
            initializeJwtProcessor();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize JWT processor", e);
        }

        // Initialize claims cache
        long refreshMinutes = jwtConfig.get("refreshMinutes") != null ?
                ((Number) jwtConfig.get("refreshMinutes")).longValue() : 5L;
        long expireHours = jwtConfig.get("expireHours") != null ?
                ((Number) jwtConfig.get("expireHours")).longValue() : 1L;

        claimsCache = CacheBuilder.newBuilder()
                .refreshAfterWrite(refreshMinutes, TimeUnit.MINUTES)
                .expireAfterAccess(expireHours, TimeUnit.HOURS)
                .build(new CacheLoader<String, List<String>>() {
                    @Override
                    public List<String> load(String token) throws Exception {
                        return loadClaimsFromToken(token);
                    }
                });

        logger.info("JwtAuthenticator setup complete");
    }

    private void initializeJwtProcessor() throws Exception {
        logger.info("Initializing JWT processor with JWKS URL: {}", jwksUrl);

        URL jwksURL = new URL(jwksUrl);
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(jwksURL);
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256,
                keySource
        );
        processor.setJWSKeySelector(keySelector);

        // Set up claims validation
        JWTClaimsSet.Builder requiredClaims = new JWTClaimsSet.Builder()
                .issuer(issuer);

        if (audience != null && !audience.isEmpty()) {
            requiredClaims.audience(audience);
        }

        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                requiredClaims.build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp"))
        ));

        this.jwtProcessor = processor;
        logger.info("JWT processor initialized successfully");
    }

    @Override
    public boolean requireAuthentication() {
        return true;
    }

    @Override
    public Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() {
        return ImmutableSet.of(DataResource.table("system_auth", "credentials"));
    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress inetAddress) {
        return new JwtSaslNegotiator();
    }

    public interface AuthenticatedUserFactory {
        AuthenticatedUser create(String username);
    }

    private AuthenticatedUserFactory userFactory = new AuthenticatedUserFactory() {
        @Override
        public AuthenticatedUser create(String username) {
            return new AuthenticatedUser(username);
        }
    };

    public void setUserFactory(AuthenticatedUserFactory factory) {
        this.userFactory = factory;
    }

    public AuthenticatedUser createUser(String username) {
        return userFactory.create(username);
    }

    /**
     * Factory method for creating AuthenticatedUser. Tests can override this to avoid static Cassandra initialization.
     */
    protected org.apache.cassandra.auth.AuthenticatedUser newAuthenticatedUser(String username) {
        return new org.apache.cassandra.auth.AuthenticatedUser(username);
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        String password = credentials.get("password");

        if (password == null || !password.startsWith("Bearer ")) {
            throw new AuthenticationException("JWT authenticator only supports Bearer tokens");
        }

        String token = password.substring("Bearer ".length()).trim();
        JwtTokenContext.setToken(token);
        return validateJwtToken(token);
    }

    private AuthenticatedUser validateJwtToken(String token) throws AuthenticationException {
        try {
            logger.debug("Validating JWT token...");

            // Process and verify token (signature, issuer, audience, expiration)
            JWTClaimsSet claims = jwtProcessor.process(token, null);

            logger.debug("JWT token validated successfully");
            logger.debug("Token claims: sub={}, iss={}, aud={}",
                    claims.getSubject(), claims.getIssuer(), claims.getAudience());

            // Extract user information
            String subject = claims.getSubject();
            if (subject == null || subject.isEmpty()) {
                throw new AuthenticationException("JWT auth failed: No subject");
            }

            // Try to extract username from various claims
            String username = extractUsername(claims);

            // Validate token claims
            validateTokenClaims(claims);

            logger.info("JWT authentication successful for user: {}", username);

            // Parse username and domain if format is user@domain
            UserInfo userInfo = parseUserFromSubject(username);
            return new DicaAuthenticatedUser(userInfo.username, token, userInfo.domain);

        } catch (BadJOSEException e) {
            logger.error("JWT signature verification failed: {}", e.getMessage());
            throw new AuthenticationException("JWT signature verification failed");
        } catch (JOSEException e) {
            logger.error("JWT verification failed: {}", e.getMessage());
            throw new AuthenticationException("Token verification failed");
        } catch (Exception e) {
            logger.error("Unexpected JWT validation error", e);
            throw new AuthenticationException("Authentication system error: " + e.getMessage());
        }
    }

    private String extractUsername(JWTClaimsSet claims) throws AuthenticationException {
        // Try multiple common username claims in order of preference
        String[] claimNames = {
                "preferred_username",  // Azure AD primary
                "upn",                 // User Principal Name
                "email",               // Email address
                "unique_name",         // Unique name
                "name",                // Display name
                "sub"                  // Subject (last resort)
        };

        for (String claimName : claimNames) {
            try {
                String value = claims.getStringClaim(claimName);
                if (value != null && !value.isEmpty()) {
                    logger.debug("Extracted username from claim '{}': {}", claimName, value);
                    return value;
                }
            } catch (Exception e) {
                // Try next claim
            }
        }

        throw new AuthenticationException("No suitable username claim found in token");
    }

    private void validateTokenClaims(JWTClaimsSet claims) throws AuthenticationException {
        try {
            // Validate expiration
            Date expirationTime = claims.getExpirationTime();
            if (expirationTime == null) {
                throw new AuthenticationException("Token missing expiration time");
            }

            Date now = new Date();
            if (now.after(expirationTime)) {
                throw new AuthenticationException("Token has expired");
            }

            // Validate not before time if present
            Date notBefore = claims.getNotBeforeTime();
            if (notBefore != null && now.before(notBefore)) {
                throw new AuthenticationException("Token not yet valid");
            }

            // Validate subject
            String subject = claims.getSubject();
            if (subject == null || subject.isEmpty()) {
                throw new AuthenticationException("Token missing subject");
            }

        } catch (Exception e) {
            throw new AuthenticationException("Invalid token claims");
        }
    }

    private UserInfo parseUserFromSubject(String subject) {
        int atIndex = subject.indexOf('@');
        if (atIndex == -1) {
            return new UserInfo(subject, null);
        }

        String username = subject.substring(0, atIndex);
        String domain = subject.substring(atIndex + 1);
        return new UserInfo(username, domain);
    }

    private List<String> loadClaimsFromToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // Try to get groups claim
            List<String> groups = claims.getStringListClaim("groups");
            if (groups != null && !groups.isEmpty()) {
                logger.debug("Loaded {} groups from token", groups.size());
                return groups;
            }

            // Try roles claim as fallback
            List<String> roles = claims.getStringListClaim("roles");
            if (roles != null && !roles.isEmpty()) {
                logger.debug("Loaded {} roles from token", roles.size());
                return roles;
            }

            logger.debug("No groups or roles found in token");
            return Collections.emptyList();

        } catch (Exception e) {
            logger.warn("Failed to load claims from token: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * SASL Negotiator implementation for JWT authentication
     */
    private class JwtSaslNegotiator implements SaslNegotiator {
        private boolean complete = false;
        private String extractedToken;

        @Override
        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
            try {
                // Parse SASL PLAIN: [authzid]\0[authid]\0[password]
                SaslPlainFields saslFields = parseSaslPlainFrame(clientResponse);
                String username = saslFields.getUsername();
                String password = saslFields.getPassword();

                // Validate Bearer token format
                if (!password.startsWith("Bearer ")) {
                    throw new AuthenticationException("JWT authenticator requires Bearer token");
                }

                this.extractedToken = password.substring("Bearer ".length()).trim();
                this.complete = true;

                logger.debug("SASL negotiation complete for user: {}", username);
                return null; // Negotiation complete

            } catch (Exception e) {
                logger.warn("SASL negotiation failed: {}", e.getMessage());
                throw new AuthenticationException("SASL authentication failed");
            }
        }

        @Override
        public boolean isComplete() {
            return complete;
        }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
            if (!complete || extractedToken == null) {
                throw new AuthenticationException("SASL negotiation not complete");
            }

            return validateJwtToken(extractedToken);
        }
    }

    /**
     * Parse SASL PLAIN authentication frame
     */
    private SaslPlainFields parseSaslPlainFrame(byte[] frame) throws AuthenticationException {
        if (frame == null || frame.length == 0) {
            throw new AuthenticationException("Empty SASL frame");
        }

        // Find null byte separators
        int firstNull = -1, secondNull = -1;
        for (int i = 0; i < frame.length; i++) {
            if (frame[i] == 0) {
                if (firstNull == -1) {
                    firstNull = i;
                } else if (secondNull == -1) {
                    secondNull = i;
                    break;
                }
            }
        }

        if (firstNull == -1 || secondNull == -1 || secondNull >= frame.length - 1) {
            throw new AuthenticationException("Invalid SASL PLAIN frame format");
        }

        String authzid = new String(frame, 0, firstNull, StandardCharsets.UTF_8);
        String username = new String(frame, firstNull + 1, secondNull - firstNull - 1, StandardCharsets.UTF_8);
        String password = new String(frame, secondNull + 1, frame.length - secondNull - 1, StandardCharsets.UTF_8);

        return new SaslPlainFields(authzid, username, password);
    }

    /**
     * Java 11 compatible class to hold SASL PLAIN fields (replaces record)
     */
    private static class SaslPlainFields {
        private final String authzid;
        private final String username;
        private final String password;

        public SaslPlainFields(String authzid, String username, String password) {
            this.authzid = authzid;
            this.username = username;
            this.password = password;
        }

        public String getAuthzid() { return authzid; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
    }

    private static class UserInfo {
        private final String username;
        private final String domain;

        public UserInfo(String username, String domain) {
            this.username = username;
            this.domain = domain;
        }

        public String getUsername() { return username; }
        public String getDomain() { return domain; }
    }
}