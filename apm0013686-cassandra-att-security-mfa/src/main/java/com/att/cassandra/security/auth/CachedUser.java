package com.att.cassandra.security.auth;

import com.att.cassandra.security.ErrorCodes;

import java.util.Set;

public final class CachedUser {
    private final String username;
    private Set<String> groups = null;
    private final long timestamp;

    public CachedUser(String username) {
        this(username, null, System.currentTimeMillis());
    }

    public CachedUser(String username, Set<String> groups, long timestamp) {
        this.username = username;
        this.groups = groups;
        this.timestamp = timestamp;
    }

    public void setGroups(Set<String> groups) {
        if (this.groups != null) {
            throw new IllegalStateException(ErrorCodes.E104 + ": Groups can only be set once");
        }
        this.groups = groups;
    }

    public String getUsername() { return username; }
    public Set<String> getGroups() { return groups; }
    public long getTimestamp() { return timestamp; }
}
