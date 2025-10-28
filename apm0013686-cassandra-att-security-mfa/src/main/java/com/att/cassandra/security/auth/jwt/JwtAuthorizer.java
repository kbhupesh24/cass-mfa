package com.att.cassandra.security.auth.jwt;

import org.apache.cassandra.auth.IAuthorizer;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.Permission;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.PermissionDetails;
import org.apache.cassandra.auth.RoleResource;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.CacheLoader;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.concurrent.TimeUnit;
import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.annotation.Nonnull;
import com.fasterxml.jackson.core.type.TypeReference;
import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.SecurityConfig;
import com.att.cassandra.security.config.KeyspaceRolesConfig;
import com.att.cassandra.security.config.RoleConfig;
import com.att.cassandra.security.auth.util.RolePermissionMapper;

/**
 * A JWT-based IAuthorizer that extracts roles/groups from the JWT's claims.
 * Uses a Guava cache to refresh claims periodically.
 */
public class JwtAuthorizer implements IAuthorizer {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthorizer.class);
    private LoadingCache<String, List<String>> claimsCache;

    private String logicalName;
    private Map<String, Object> myConfig;

    public JwtAuthorizer() {}
    public JwtAuthorizer(String logicalName) { this.logicalName = logicalName; }
    public void setLogicalName(String logicalName) { this.logicalName = logicalName; }

    @Override
    public void validateConfiguration() throws ConfigurationException {
        // no-op
    }

    @Override
    @SuppressWarnings("unchecked")
    public void setup() {
        // Load config for this logicalName
        SecurityConfig secConfig = ConfigLoader.load();
        Map<String, Object> authorizerConfigs = secConfig.getAuthorizers();
        myConfig = null;
        if (authorizerConfigs != null && logicalName != null) {
            Object raw = authorizerConfigs.get(logicalName);
            if (raw instanceof Map) {
                myConfig = (Map<String, Object>) raw;
            }
        }
        if (myConfig == null) {
            throw new IllegalStateException("No config found for JwtAuthorizer logicalName=" + logicalName);
        }
        // resolve this logical authorizer's config
        // Find the config for this instance (by logical name or class)
        // load JWT settings from myConfig
        String userInfoUrl = (String) myConfig.get("userInfoUrl");
        long refreshMinutes = myConfig.get("refreshMinutes") != null ? Long.parseLong(myConfig.get("refreshMinutes").toString()) : 5L;
        long expireHours = myConfig.get("expireHours") != null ? Long.parseLong(myConfig.get("expireHours").toString()) : 1L;
        // local HTTP client and JSON mapper for UserInfo calls
        final HttpClient client = HttpClient.newHttpClient();
        final ObjectMapper mapper = new ObjectMapper();
        // refresh claims after 'refreshMinutes'; expire cache entries after 'expireHours'
        claimsCache = CacheBuilder.newBuilder()
            .refreshAfterWrite(refreshMinutes, TimeUnit.MINUTES)
            .expireAfterAccess(expireHours, TimeUnit.HOURS)
            .build(new CacheLoader<String, List<String>>() {
                @Override
                public @Nonnull List<String> load(@Nonnull String token) throws Exception {
                    // If a UserInfo endpoint is configured, call it to fetch up-to-date claims
                    if (userInfoUrl != null && !userInfoUrl.isEmpty()) {
                        try {
                            HttpRequest req = HttpRequest.newBuilder()
                                .uri(URI.create(userInfoUrl))
                                .header("Authorization", "Bearer " + token)
                                .GET()
                                .build();
                            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                            if (resp.statusCode() == 200) {
                                Map<String, Object> data = mapper.readValue(
                                    resp.body(), new TypeReference<Map<String, Object>>(){});
                                // try roles claim, then fallback to groups claim
                                Object claim = data.get("roles");
                                if (!(claim instanceof List) || ((List<?>)claim).isEmpty()) {
                                    claim = data.get("groups");
                                }
                                if (claim instanceof List) {
                                    return ((List<?>) claim).stream()
                                        .map(Object::toString)
                                        .collect(Collectors.toList());
                                }
                            } else {
                                logger.warn("UserInfo endpoint returned status {}", resp.statusCode());
                            }
                        } catch (Exception e) {
                            logger.warn("Error calling UserInfo endpoint: {}", e.getMessage());
                        }
                        // fallback to JWT parsing
                    }
                    SignedJWT jwt = SignedJWT.parse(token);
                    JWTClaimsSet claims = jwt.getJWTClaimsSet();
                    logger.debug("Available claims: {}", claims.getClaims().keySet());

                    // try roles claim first, then groups claim
                    List<String> roles = claims.getStringListClaim("roles");
                    logger.debug("Roles from 'roles' claim: {}", roles);
                    if (roles == null || roles.isEmpty()) {
                        roles = new ArrayList<>();
                    }

                    List<String> groupStrings = claims.getStringListClaim("groups");
//                    if (groupStrings != null && !groupStrings.isEmpty()) {
//                        roles.addAll(groupStrings);
//                    }

                    // If still null, try alternative extraction methods
                    if (roles == null || roles.isEmpty()) {
                        Object groupsObj = claims.getClaim("groups");
                        if (groupsObj instanceof List) {
                            roles = ((List<?>) groupsObj).stream()
                                    .map(Object::toString)
                                    .collect(Collectors.toList());
                        }
                    }
                    return roles != null ? roles : Collections.emptyList();
                }
            });
    }

    @Override
    public Set<Permission> authorize(AuthenticatedUser authnUser, IResource resource) {
        String token = "authnUser.getJwtToken()";
        if (token == null) {
            logger.warn("No JWT token found. AuthUser: {}, Resource: {}",
                    authnUser.getName(), resource.getName());
            return Collections.emptySet();
        }
        List<String> groups;
        try {
            groups = claimsCache.get(token);
        } catch (Exception e) {
            logger.warn("Failed to load claims for token: {}", e.getMessage());
            return Collections.emptySet();
        }
        // --- New local roles/permissions mapping logic ---
        SecurityConfig config = ConfigLoader.load();
        List<KeyspaceRolesConfig> keyspaces = config.getKeyspaces();
        List<RoleConfig> defaultRoles = config.getDefaultRoles();
        return RolePermissionMapper.mapGroupsToPermissions(groups, resource, keyspaces, defaultRoles);
    }

    @Override
    public Set<PermissionDetails> list(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, RoleResource grantee)
            throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException("E110: Listing permissions not supported in JwtAuthorizer");
    }

    @Override
    public Set<Permission> grant(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, RoleResource grantee)
            throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException("E110: Granting permissions not supported in JwtAuthorizer");
    }

    @Override
    public Set<Permission> revoke(AuthenticatedUser performer, Set<Permission> permissions, IResource resource, RoleResource grantee)
            throws RequestValidationException, RequestExecutionException {
        throw new UnsupportedOperationException("E110: Revoking permissions not supported in JwtAuthorizer");
    }

    @Override
    public void revokeAllFrom(RoleResource grantee) {
        throw new UnsupportedOperationException("E110: Revoking all permissions from grantee not supported in JwtAuthorizer");
    }

    @Override
    public void revokeAllOn(IResource resource) {
        throw new UnsupportedOperationException("E110: Revoking all permissions on resource not supported in JwtAuthorizer");
    }

    @Override
    public Set<? extends IResource> protectedResources() {
        return Collections.singleton(DataResource.table("system_auth", "role_permissions"));
    }
}
