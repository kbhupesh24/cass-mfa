package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CacheConfigTest {
    @Test
    void testGettersAndSetters() {
        CacheConfig config = new CacheConfig();
        config.setTtlSeconds(123);
        config.setCleanupAfterSeconds(456);
        assertEquals(123, config.getTtlSeconds());
        assertEquals(456, config.getCleanupAfterSeconds());
    }
}
