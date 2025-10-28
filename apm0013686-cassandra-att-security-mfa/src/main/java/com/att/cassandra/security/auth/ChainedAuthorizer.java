package com.att.cassandra.security.auth;

import org.apache.cassandra.auth.*;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;
import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.SecurityConfig;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.TreeSet;
import java.util.HashSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ChainedAuthorizer: delegates authorization to a configurable list of IAuthorizer plugins, merging permissions.
 * Example config in cassandra.yaml:
 *   authorizer_chain:
 *     - com.att.cassandra.security.auth.ldap.LdapAuthorizer
 *     - org.apache.cassandra.auth.CassandraAuthorizer
 *     - com.att.cassandra.security.auth.jwt.JwtAuthorizer
 */
public class ChainedAuthorizer implements IAuthorizer {
    private static final Logger logger = LoggerFactory.getLogger(ChainedAuthorizer.class);
    private List<IAuthorizer> authorizers = new ArrayList<>();

    @Override
    public void validateConfiguration() throws ConfigurationException {}

    @Override
    public void setup() {
        logger.info("[ChainedAuthorizer] setup() called");
        // Load security configuration, tests may override via ConfigLoader.setTestConfig
        SecurityConfig config = ConfigLoader.load();
        // Extract chain and plugin configs
        List<String> chain = (config != null && config.getChained() != null)
                ? config.getChained().getAuthorizers() : null;
        Map<String, Object> pluginConfigs = (config != null)
                ? config.getAuthorizers() : null;
        if (chain == null || chain.isEmpty() || pluginConfigs == null) {
            logger.error("[ChainedAuthorizer] No authorizers configured in security.yaml");
            throw new IllegalStateException("No authorizers configured in security.yaml");
        }
        authorizers.clear();
        for (String logicalName : chain) {
            Object[] resolved = ConfigLoader.resolvePluginConfig(pluginConfigs, logicalName);
            String className = (String) resolved[0];
            try {
                Class<?> clazz = Class.forName(className.trim());
                IAuthorizer authz;
                try {
                    authz = (IAuthorizer) clazz.getDeclaredConstructor(String.class).newInstance(logicalName);
                } catch (NoSuchMethodException e) {
                    // Fallback to no-arg constructor for built-in authorizers
                    authz = (IAuthorizer) clazz.getDeclaredConstructor().newInstance();
                }
                logger.info("[ChainedAuthorizer] Adding authorizer: {} as {}", className, logicalName);
                authz.setup();
                authorizers.add(authz);
            } catch (Exception e) {
                logger.error("[ChainedAuthorizer] Failed to instantiate authorizer: {}", className, e);
                throw new RuntimeException("Failed to instantiate authorizer: " + className, e);
            }
        }
    }

    @Override
    public Set<Permission> authorize(AuthenticatedUser user, IResource resource) {
        logger.debug("[ChainedAuthorizer] authorize called for user: {} resource: {}", user.getName(), resource.getName());
        Set<Permission> merged = new TreeSet<>();
        for (IAuthorizer authz : authorizers) {
            try {
                logger.debug("[ChainedAuthorizer] Calling authorize on: {}", authz.getClass().getName());
                merged.addAll(authz.authorize(user, resource));
            } catch (Exception e) {
                logger.warn("[ChainedAuthorizer] Exception in authorize for {}: {}", authz.getClass().getName(), e.getMessage());
            }
        }
        return merged;
    }

    @Override
    public Set<Permission> grant(AuthenticatedUser user, Set<Permission> perms, IResource resource, RoleResource grantee) throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException("Grant not supported in ChainedAuthorizer");
    }

    @Override
    public Set<PermissionDetails> list(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, RoleResource grantee) throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException("List not supported in ChainedAuthorizer");
    }

    @Override
    public Set<Permission> revoke(AuthenticatedUser user, Set<Permission> perms, IResource resource, RoleResource grantee) throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException("Revoke not supported in ChainedAuthorizer");
    }

    @Override
    public void revokeAllFrom(RoleResource role) {
        throw new UnsupportedOperationException("RevokeAllFrom not supported in ChainedAuthorizer");
    }

    @Override
    public void revokeAllOn(IResource resource) {
        throw new UnsupportedOperationException("RevokeAllOn not supported in ChainedAuthorizer");
    }

    @Override
    public Set<? extends IResource> protectedResources() {
        Set<IResource> all = new HashSet<>();
        for (IAuthorizer authz : authorizers) {
            all.addAll(authz.protectedResources());
        }
        return all;
    }
}
