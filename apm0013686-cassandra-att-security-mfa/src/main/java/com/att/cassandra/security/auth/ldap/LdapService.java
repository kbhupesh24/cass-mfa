package com.att.cassandra.security.auth.ldap;

import com.att.cassandra.security.auth.CachedUser;
import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.LdapConfig;
import com.att.cassandra.security.config.SecurityConfig;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.unboundid.ldap.sdk.*;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLSocketFactory;

public class LdapService {
    private static final Map<String, LdapService> instances = new java.util.concurrent.ConcurrentHashMap<>();
    private SecurityConfig securityConfig;
    private LoadingCache<String, CachedUser> cache;
    static LdapService instance = null;
    private LdapConfig config;
    static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapService.class);
    // For testing: allow injection of a test config
    public static SecurityConfig testConfig = null;
    public static void setTestConfig(SecurityConfig config) { testConfig = config; }
    public static void clearTestConfig() { testConfig = null; }

    public LdapService(LdapConfig config) {
        this.config = config;
    }

    public static LdapService getInstance(String logicalName) {
        if (instances.containsKey(logicalName)) {
            return instances.get(logicalName);
        }
        SecurityConfig securityConfig = (testConfig != null) ? testConfig : ConfigLoader.load();
        Map<String, Object> externalServices = securityConfig.getExternalServices();
        if (externalServices == null || !externalServices.containsKey(logicalName)) {
            throw new IllegalArgumentException("No external_service config found for logical name: " + logicalName);
        }
        Object raw = externalServices.get(logicalName);
        com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
        LdapConfig ldapConfig = om.convertValue(raw, LdapConfig.class);
        LdapService ldapService = new LdapService(ldapConfig);
        CacheBuilder<Object, Object> builder = CacheBuilder.newBuilder()
                .refreshAfterWrite(securityConfig.getCache().getTtlSeconds(), TimeUnit.SECONDS)
                .expireAfterAccess(securityConfig.getCache().getCleanupAfterSeconds(), TimeUnit.SECONDS);
        LoadingCache<String, CachedUser> cache = builder.build(new CacheLoader<String, CachedUser>() {
            @Override
            public CachedUser load(@Nonnull String username) throws Exception {
                return new CachedUser(username, ldapService.fetchUserGroups(username), System.currentTimeMillis());
            }
            @Override
            public com.google.common.util.concurrent.ListenableFuture<CachedUser> reload(@Nonnull String key,
                    @Nonnull CachedUser oldValue) throws Exception {
                return com.google.common.util.concurrent.Futures.immediateFuture(load(key));
            }
        });
        ldapService.cache = cache;
        instances.put(logicalName, ldapService);
        return ldapService;
    }

    // Add a static helper for tests to set the singleton instance
    public static void setInstanceForTest(LdapService service) {
        instance = service;
    }

    // Add package-private setter for logger for testability
    static void setLoggerForTest(org.slf4j.Logger testLogger) {
        logger = testLogger;
    }

    public LoadingCache<String, CachedUser> getCache() {
        return cache;
    }

    public SecurityConfig getConfig() {
        return securityConfig;
    }

    // Helper to find the user's DN by searching userBaseDn for userAttribute=username
    String findUserDn(String username) throws LDAPException {
        if (config == null || config.getUserBaseDn() == null || config.getUserAttribute() == null || username == null)
            return null;
        LDAPConnection conn = null;
        try {
            LDAPURL ldapUrl = new LDAPURL(config.getUrl());
            if (config.isTrustAllCerts()) {
                SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
                SSLSocketFactory socketFactory = sslUtil.createSSLSocketFactory();
                conn = new LDAPConnection(socketFactory, ldapUrl.getHost(), ldapUrl.getPort(), config.getBindUser(), config.getBindPassword());
            } else {
                conn = new LDAPConnection(ldapUrl.getHost(), ldapUrl.getPort(), config.getBindUser(), config.getBindPassword());
            }
            Filter filter = Filter.createEqualityFilter(config.getUserAttribute(), username);
            SearchRequest searchRequest = new SearchRequest(
                config.getUserBaseDn(), SearchScope.SUB, filter
            );
            SearchResult result = conn.search(searchRequest);
            if (!result.getSearchEntries().isEmpty()) {
                return result.getSearchEntries().get(0).getDN();
            }
            return null;
        } catch (LDAPException | GeneralSecurityException e) {
            logger.warn("[LdapService] Failed to find user DN for {}: {}", username, e.getMessage());
            throw new LDAPException(ResultCode.CONNECT_ERROR, e.getMessage(), e);
        } finally {
            if (conn != null) conn.close();
        }
    }

    public boolean authenticateBind(String username, String password) {
        if (username == null || password == null) return false;
        String userDn;
        try {
            userDn = findUserDn(username);
        } catch (LDAPException e) {
            logger.warn("[LdapService] Could not resolve user DN for {}: {}", username, e.getMessage());
            return false;
        }
        if (userDn == null) return false;
        logger.info("[LdapService] Attempting LDAP bind for userDn: {}", userDn);
        LDAPConnection connection = null;
        try {
            LDAPURL ldapUrl = new LDAPURL(config.getUrl());
            if (config.isTrustAllCerts()) {
                logger.warn("[LdapService] trustAllCerts is enabled! Disabling certificate validation for LDAP connection.");
                SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
                SSLSocketFactory socketFactory = sslUtil.createSSLSocketFactory();
                connection = new LDAPConnection(socketFactory, ldapUrl.getHost(), ldapUrl.getPort(), userDn, password);
            } else {
                connection = new LDAPConnection(ldapUrl.getHost(), ldapUrl.getPort(), userDn, password);
            }
            logger.info("[LdapService] LDAP bind successful for userDn: {}", userDn);
            return true;
        } catch (LDAPException e) {
            logger.warn("[LdapService] LDAPException during bind for userDn: {}: {}", userDn, e.getMessage());
            return false;
        } catch (Exception e) {
            logger.error("[LdapService] Exception during bind for userDn: {}: {}", userDn, e.getMessage(), e);
            return false;
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }

    public Set<String> fetchUserGroups(String username) throws LDAPException {
        if (username == null || username.isEmpty()) throw new IllegalArgumentException("username required");
        Set<String> groups = new HashSet<>();
        String userDn = findUserDn(username);
        if (userDn == null) {
            logger.warn("[LdapService] userDn not found for '{}', returning empty group set", username);
            return groups;
        }
        LDAPConnection conn = null;
        try {
            // bind as admin
            LDAPURL ldapUrl = new LDAPURL(config.getUrl());
            if (config.isTrustAllCerts()) {
                SSLUtil sslUtil = new SSLUtil(null, new TrustAllTrustManager());
                SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
                conn = new LDAPConnection(sslSocketFactory, ldapUrl.getHost(), ldapUrl.getPort(), config.getBindUser(), config.getBindPassword());
            } else {
                conn = new LDAPConnection(ldapUrl.getHost(), ldapUrl.getPort(), config.getBindUser(), config.getBindPassword());
            }
            String groupObjectClass = config.getGroupObjectClass() != null ? config.getGroupObjectClass() : "groupOfNames";
            String groupAttribute = config.getGroupAttribute() != null ? config.getGroupAttribute() : "cn";
            String groupMemberAttribute = config.getGroupMemberAttribute() != null ? config.getGroupMemberAttribute() : "member";
            Filter filter = Filter.createANDFilter(
                Filter.createEqualityFilter("objectClass", groupObjectClass),
                Filter.createEqualityFilter(groupMemberAttribute, userDn)
            );
            SearchRequest searchRequest = new SearchRequest(
                config.getGroupBaseDn(), SearchScope.SUB, filter, groupAttribute
            );
            SearchResult result = conn.search(searchRequest);
            for (SearchResultEntry entry : result.getSearchEntries()) {
                String groupName = entry.getAttributeValue(groupAttribute);
                if (groupName != null) {
                    groups.add(groupName);
                }
            }
        } catch (LDAPException e) {
            logger.warn("{} Failed to fetch groups for user {}: {}", com.att.cassandra.security.ErrorCodes.W202, username, e.getMessage());
            throw e;
        } catch (GeneralSecurityException e) {
            logger.warn("{} Failed to connect {}: {}", com.att.cassandra.security.ErrorCodes.W202, username, e.getMessage());
            throw new LDAPException(ResultCode.CONNECT_ERROR, e.getMessage(), e);
        } finally {
            if (conn != null) conn.close();
        }
        if (groups.isEmpty()) {
            logger.warn("{} User {} has no groups in LDAP", com.att.cassandra.security.ErrorCodes.W201, username);
        }
        return groups;
    }
}
