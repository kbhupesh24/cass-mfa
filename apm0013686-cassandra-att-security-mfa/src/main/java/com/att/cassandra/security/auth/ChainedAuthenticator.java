package com.att.cassandra.security.auth;

import org.apache.cassandra.auth.*;
import org.apache.cassandra.exceptions.AuthenticationException;
import java.net.InetAddress;
import java.util.*;
import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.SecurityConfig;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ChainedAuthenticator: delegates authentication to a configurable list of IAuthenticator plugins.
 * Example config in cassandra.yaml:
 *   authenticator_chain:
 *     - org.apache.cassandra.auth.PasswordAuthenticator
 *     - com.att.cassandra.security.auth.ldap.LdapAuthenticator
 *     - com.att.cassandra.security.auth.jwt.JwtAuthenticator
 */
public class ChainedAuthenticator implements IAuthenticator {
    private static final Logger logger = LoggerFactory.getLogger(ChainedAuthenticator.class);
    private List<IAuthenticator> authenticators = new ArrayList<>();

    // For testing: allow injection of a test config
    static SecurityConfig testConfig = null;
    static void setTestConfig(SecurityConfig config) { testConfig = config; }
    static void clearTestConfig() { testConfig = null; }

    @Override
    public void validateConfiguration() {}

    @Override
    public void setup() {
        logger.info("[ChainedAuthenticator] setup() called");
        authenticators.clear(); // Ensure no static or stale state between test runs
        List<String> chain = null;
        Map<String, Object> pluginConfigs = null;
        try {
            SecurityConfig config = (testConfig != null) ? testConfig : ConfigLoader.load();
            if (config != null && config.getChained() != null && config.getChained().getAuthenticators() != null) {
                chain = config.getChained().getAuthenticators();
                pluginConfigs = config.getAuthenticators();
            }
        } catch (Exception e) {
            logger.error("[ChainedAuthenticator] Exception loading config: ", e);
        }
        if (chain == null || chain.isEmpty() || pluginConfigs == null) {
            logger.error("[ChainedAuthenticator] No authenticators configured in security.yaml");
            throw new IllegalStateException("No authenticators configured in security.yaml");
        }
        for (String logicalName : chain) {
            Object[] resolved = ConfigLoader.resolvePluginConfig(pluginConfigs, logicalName);
            String className = (String) resolved[0];
            try {
                Class<?> clazz = Class.forName(className.trim());
                IAuthenticator authn;
                try {
                    authn = (IAuthenticator) clazz.getDeclaredConstructor(String.class).newInstance(logicalName);
                } catch (NoSuchMethodException e) {
                    // Fallback to no-arg constructor for built-in authorizers
                    try {
                        authn = (IAuthenticator) clazz.getDeclaredConstructor().newInstance();
                    } catch (NoSuchMethodException e2) {
                        // Fallback to boolean constructor (test dummy supporting class)
                        authn = (IAuthenticator) clazz.getDeclaredConstructor(boolean.class).newInstance(false);
                    }
                }
                logger.info("[ChainedAuthenticator] Adding authenticator: {} as {}", className, logicalName);
                authn.setup();
                authenticators.add(authn);
            } catch (Exception e) {
                logger.error("[ChainedAuthenticator] Failed to instantiate authenticator: {}", className, e);
                throw new RuntimeException("Failed to instantiate authenticator: " + className, e);
            }
        }
        // If you have similar logic for authorizers, apply the same pattern:
        // for (String logicalName : authorizerChain) { ... }
    }

    /**
     * Each authenticator can optionally implement SupportsCredentialType.
     * If so, we use it to check if it can handle the credential type.
     * Otherwise, we try all authenticators in order (legacy fallback).
     */
    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress) {
        logger.debug("[ChainedAuthenticator] newSaslNegotiator for client: {}", clientAddress);
        return new ChainedSaslNegotiator(clientAddress);
    }

    /**
     * Optional interface for authenticators to declare what credential types they support.
     */
    public interface SupportsCredentialType {
        boolean supports(byte[] initialSaslPayload);
    }

    private class ChainedSaslNegotiator implements SaslNegotiator {
        private final InetAddress clientAddress;
        private SaslNegotiator current;
        private boolean attemptedDispatch = false;
        private final List<String> errorMessages = new ArrayList<>();
        private boolean anySupported = false;

        ChainedSaslNegotiator(InetAddress clientAddress) {
            this.clientAddress = clientAddress;
            this.current = null;
        }

        @Override
        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
            logger.debug("[ChainedAuthenticator] evaluateResponse called");
            if (!attemptedDispatch) {
                attemptedDispatch = true;
                // Try each authenticator in order
                for (IAuthenticator authn : authenticators) {
                    boolean shouldTry = false;
                    if (authn instanceof SupportsCredentialType) {
                        if (((SupportsCredentialType)authn).supports(clientResponse)) {
                            anySupported = true;
                            shouldTry = true;
                        }
                    } else {
                        // Always try non-SupportsCredentialType authenticators as fallback
                        shouldTry = true;
                    }
                    if (shouldTry) {
                        logger.info("[ChainedAuthenticator] Dispatching to authenticator: {}", authn.getClass().getName());
                        SaslNegotiator negotiator = authn.newSaslNegotiator(clientAddress);
                        try {
                            byte[] result = negotiator.evaluateResponse(clientResponse);
                            current = negotiator;
                            return result;
                        } catch (AuthenticationException e) {
                            logger.warn("[ChainedAuthenticator] Authenticator {} failed: {}", authn.getClass().getName(), e.getMessage());
                            errorMessages.add(authn.getClass().getSimpleName() + ": " + e.getMessage());
                            // continue to next authenticator
                        }
                    }
                }
            }
            if (!anySupported && authenticators.stream().anyMatch(a -> !(a instanceof SupportsCredentialType))) {
                // If only non-SupportsCredentialType authenticators were tried, treat as supported
                anySupported = true;
            }
            if (!anySupported) {
                logger.error("[ChainedAuthenticator] No authenticators configured to handle provided credential type");
                throw new AuthenticationException("No authenticators configured to handle provided credential type");
            }
            logger.error("[ChainedAuthenticator] No authenticators succeeded. Errors: {}", errorMessages);
            throw new AuthenticationException("No authenticators succeeded. Errors: " + errorMessages);
        }

        @Override
        public boolean isComplete() {
            return current != null && current.isComplete();
        }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
            if (current == null) throw new AuthenticationException("No successful authenticator");
            return current.getAuthenticatedUser();
        }
    }

    @Override
    public boolean requireAuthentication() { return true; }

    @Override
    public Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() { return Collections.emptySet(); }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        logger.debug("[ChainedAuthenticator] legacyAuthenticate called");
        List<String> errorMessages = new ArrayList<>();
        boolean anySupported = false;
        for (IAuthenticator authn : authenticators) {
            if (authn instanceof SupportsCredentialType) {
                String username = credentials.get("username");
                String password = credentials.get("password");
                byte[] payload = (username + "\0" + password).getBytes();
                if (((SupportsCredentialType)authn).supports(payload)) {
                    anySupported = true;
                    logger.info("[ChainedAuthenticator] legacyAuthenticate dispatching to: {}", authn.getClass().getName());
                    try {
                        return authn.legacyAuthenticate(credentials);
                    } catch (AuthenticationException e) {
                        logger.warn("[ChainedAuthenticator] Authenticator {} failed: {}", authn.getClass().getName(), e.getMessage());
                        errorMessages.add(authn.getClass().getSimpleName() + ": " + e.getMessage());
                        // continue to next authenticator
                    }
                }
            }
        }
        if (!anySupported) {
            logger.error("[ChainedAuthenticator] No authenticators configured to handle provided credential type");
            throw new AuthenticationException("No authenticators configured to handle provided credential type");
        }
        logger.error("[ChainedAuthenticator] No authenticators succeeded. Errors: {}", errorMessages);
        throw new AuthenticationException("No authenticators succeeded. Errors: " + errorMessages);
    }
}
