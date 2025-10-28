package com.att.cassandra.security.config;

import java.util.List;

public class ResourcePermissionConfig {
    private String type;
    private String name;
    private List<String> permissions;

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public List<String> getPermissions() { return permissions; }
    public void setPermissions(List<String> permissions) { this.permissions = permissions; }
}
