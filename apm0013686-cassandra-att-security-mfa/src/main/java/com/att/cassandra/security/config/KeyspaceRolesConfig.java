package com.att.cassandra.security.config;

import java.util.List;

public class KeyspaceRolesConfig {
    private String name;
    private String rolePrefix;
    private List<RoleConfig> roles;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getRolePrefix() { return rolePrefix; }
    public void setRolePrefix(String rolePrefix) { this.rolePrefix = rolePrefix; }
    public List<RoleConfig> getRoles() { return roles; }
    public void setRoles(List<RoleConfig> roles) { this.roles = roles; }
}
