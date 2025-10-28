package com.att.cassandra.security.config;

import java.util.List;

public class RoleConfig {
    private String name;
    private List<ResourcePermissionConfig> resources;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public List<ResourcePermissionConfig> getResources() { return resources; }
    public void setResources(List<ResourcePermissionConfig> resources) { this.resources = resources; }
}
