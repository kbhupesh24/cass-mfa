package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JwtConfigTest {
    @Test
    void testGettersAndSetters() {
        JwtConfig config = new JwtConfig();
        config.setUserInfoUrl("https://userinfo");
        config.setRefreshMinutes(30);
        config.setExpireHours(48);
        assertEquals("https://userinfo", config.getUserInfoUrl());
        assertEquals(30, config.getRefreshMinutes());
        assertEquals(48, config.getExpireHours());
    }
}
