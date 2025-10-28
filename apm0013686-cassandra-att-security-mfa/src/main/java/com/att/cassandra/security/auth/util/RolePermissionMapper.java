package com.att.cassandra.security.auth.util;

import com.att.cassandra.security.config.KeyspaceRolesConfig;
import com.att.cassandra.security.config.RoleConfig;
import com.att.cassandra.security.config.ResourcePermissionConfig;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.auth.Permission;

import java.util.*;

public class RolePermissionMapper {
    // Prevent instantiation
    private RolePermissionMapper() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Map user groups/roles to Cassandra permissions using local YAML-defined roles.
     * @param groups The user's groups/roles from LDAP/JWT
     * @param resource The Cassandra resource being accessed
     * @param keyspaces List of keyspace role configs
     * @param defaultRoles Fallback roles if no keyspace match
     * @return Set of Cassandra permissions
     */
    public static Set<Permission> mapGroupsToPermissions(Collection<String> groups, IResource resource, List<KeyspaceRolesConfig> keyspaces, List<RoleConfig> defaultRoles) {
        // Determine keyspace from resource, fallback to defaultRoles if not found
        String keyspace = null;
        if (resource instanceof DataResource) {
            try {
                keyspace = ((DataResource) resource).getKeyspace();
            } catch (Exception e) {
                // ROOT or other resources without keyspace will throw exception
                System.out.println("DEBUG: Unable to get keyspace from resource: " + e.getMessage());
            }
        }
        KeyspaceRolesConfig ksConfig = null;
        if (keyspace != null && keyspaces != null) {
            for (KeyspaceRolesConfig k : keyspaces) {
                if (keyspace.equalsIgnoreCase(k.getName())) {
                    ksConfig = k;
                    break;
                }
            }
        }
        // When keyspace is not determined (ROOT/ALL resources), try all keyspace configs
        if (ksConfig == null && keyspaces != null && !keyspaces.isEmpty()) {
            // Try to find a matching role in any keyspace config
            if (groups != null) {
                for (KeyspaceRolesConfig k : keyspaces) {
                    String rolePrefix = (k.getRolePrefix() != null) ? k.getRolePrefix() : "";
                    String expectedPrefix = rolePrefix.isEmpty() || rolePrefix.endsWith("-") ? rolePrefix : rolePrefix + "-";
                    for (String group : groups) {
                        if (group.startsWith(expectedPrefix)) {
                            String roleName = group.substring(expectedPrefix.length());
                            List<RoleConfig> kRoles = k.getRoles();
                            if (kRoles != null) {
                                for (RoleConfig role : kRoles) {
                                    if (role.getName() != null && role.getName().equalsIgnoreCase(roleName)) {
                                        ksConfig = k;
                                        break;
                                    }
                                }
                            }
                            if (ksConfig != null) break;
                        }
                    }
                    if (ksConfig != null) break;
                }
            }
        }
        List<RoleConfig> roles = (ksConfig != null) ? ksConfig.getRoles() : defaultRoles;
        // Use empty prefix when no keyspace config (fallback roles)
        String rolePrefix = (ksConfig != null && ksConfig.getRolePrefix() != null) ? ksConfig.getRolePrefix() : "";
        String expectedPrefix = rolePrefix;
        // Ensure prefix ends with dash if not empty and not already
        if (!expectedPrefix.isEmpty() && !expectedPrefix.endsWith("-")) {
            expectedPrefix = expectedPrefix + "-";
        }

        // Build a map for fast role lookup by name (case-insensitive)
        Map<String, RoleConfig> roleMap = new HashMap<>();
        if (roles != null) {
            for (RoleConfig role : roles) {
                String name = role.getName();
                if (name != null) {
                    roleMap.put(name.toLowerCase(), role);
                }
            }
        }

        Set<Permission> permissions = new TreeSet<>();
        if (roles != null && groups != null) {
            for (String group : groups) {
                System.out.println("DEBUG: group=" + group + ", expectedPrefix=" + expectedPrefix);
                if (!group.startsWith(expectedPrefix)) {
                    System.out.println("DEBUG: group does not start with expectedPrefix, skipping");
                    continue;
                }
                String roleName = group.substring(expectedPrefix.length());
                System.out.println("DEBUG: roleName after prefix strip=" + roleName);
                RoleConfig role = roleMap.get(roleName.toLowerCase());
                if (role != null) {
                    for (ResourcePermissionConfig rpc : role.getResources()) {
                        boolean typeMatches = false;
                        boolean nameMatches = false;
                        String tableName = null;
                        if (resource instanceof DataResource) {
                            typeMatches = "data".equalsIgnoreCase(rpc.getType());
                            try {
                                tableName = ((DataResource) resource).getTable();
                                System.out.println("DEBUG: DataResource tableName=" + tableName);
                            } catch (Exception e) {
                                // ALL TABLES or other resources without specific table will throw exception
                                System.out.println("DEBUG: Unable to get table from resource: " + e.getMessage());
                            }
                            nameMatches = "*".equals(rpc.getName()) || (tableName != null && rpc.getName().equalsIgnoreCase(tableName));
                        } else {
                            typeMatches = resource.getName().startsWith(rpc.getType());
                            nameMatches = "*".equals(rpc.getName()) || resource.getName().contains(rpc.getName());
                        }
                        System.out.println("DEBUG: typeMatches=" + typeMatches + ", nameMatches=" + nameMatches);
                        if (typeMatches && nameMatches) {
                            for (String perm : rpc.getPermissions()) {
                                try {
                                    if ("ALL".equalsIgnoreCase(perm)) {
                                        // Expand ALL to all available permissions
                                        System.out.println("DEBUG: expanding ALL to all permissions");
                                        permissions.add(Permission.CREATE);
                                        permissions.add(Permission.ALTER);
                                        permissions.add(Permission.DROP);
                                        permissions.add(Permission.SELECT);
                                        permissions.add(Permission.MODIFY);
                                        permissions.add(Permission.AUTHORIZE);
                                        permissions.add(Permission.DESCRIBE);
                                        permissions.add(Permission.EXECUTE);
                                    } else {
                                        System.out.println("DEBUG: granting permission " + perm);
                                        permissions.add(Permission.valueOf(perm));
                                    }
                                } catch (Exception e) {
                                    System.out.println("DEBUG: failed to grant permission " + perm + ": " + e.getMessage());
                                }
                            }
                        }
                    }
                } else {
                    System.out.println("DEBUG: role not found in roleMap for roleName=" + roleName.toLowerCase());
                }
            }
        }
        return permissions;
    }
}
