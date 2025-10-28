package com.att.cassandra.security.auth.jwt;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JwtTokenContextTest {
    @Test
    void testSetGetAndClearToken() {
        JwtTokenContext.setToken("abc123");
        assertEquals("abc123", JwtTokenContext.getToken());
        JwtTokenContext.clear();
        assertNull(JwtTokenContext.getToken());
    }

    @Test
    void testConstructorCoverage() {
        // Just instantiate to cover the implicit constructor
        new JwtTokenContext();
    }
}
