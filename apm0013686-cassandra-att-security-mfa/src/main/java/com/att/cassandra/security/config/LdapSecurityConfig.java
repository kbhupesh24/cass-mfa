package com.att.cassandra.security.config;

import java.util.List;

public class LdapSecurityConfig {
    private LdapConfig ldap;
    private KeyspaceRolesConfig keyspace;
    private CacheConfig cache;
    private List<KeyspaceRolesConfig> keyspaces;
    private List<RoleConfig> defaultRoles;
    private JwtConfig jwt;

    // getters and setters
    public LdapConfig getLdap() { return ldap; }
    public void setLdap(LdapConfig ldap) { this.ldap = ldap; }
    public KeyspaceRolesConfig getKeyspace() { return keyspace; }
    public void setKeyspace(KeyspaceRolesConfig keyspace) { this.keyspace = keyspace; }
    public CacheConfig getCache() { return cache; }
    public void setCache(CacheConfig cache) { this.cache = cache; }
    public List<KeyspaceRolesConfig> getKeyspaces() { return keyspaces; }
    public void setKeyspaces(List<KeyspaceRolesConfig> keyspaces) { this.keyspaces = keyspaces; }
    public List<RoleConfig> getDefaultRoles() { return defaultRoles; }
    public void setDefaultRoles(List<RoleConfig> defaultRoles) { this.defaultRoles = defaultRoles; }
    public JwtConfig getJwt() { return jwt; }
    public void setJwt(JwtConfig jwt) { this.jwt = jwt; }
}
