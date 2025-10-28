package com.att.cassandra.security.config;

public class CacheConfig {
    private long ttlSeconds;
    private long cleanupAfterSeconds;

    public long getTtlSeconds() { return ttlSeconds; }
    public void setTtlSeconds(long ttlSeconds) { this.ttlSeconds = ttlSeconds; }
    public long getCleanupAfterSeconds() { return cleanupAfterSeconds; }
    public void setCleanupAfterSeconds(long cleanupAfterSeconds) { this.cleanupAfterSeconds = cleanupAfterSeconds; }
}
