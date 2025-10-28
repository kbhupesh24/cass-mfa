// Test double for org.apache.cassandra.auth.AuthenticatedUser
package org.apache.cassandra.auth;

import java.util.Collections;
import java.util.Set;

public class AuthenticatedUser {
    private final String name;
    public AuthenticatedUser(String name) { this.name = name; }
    public String getName() { return name; }
    public Set<RoleResource> getRoles() { return Collections.emptySet(); }
}
