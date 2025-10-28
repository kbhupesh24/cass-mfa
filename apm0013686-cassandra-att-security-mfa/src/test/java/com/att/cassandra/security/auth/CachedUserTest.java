package com.att.cassandra.security.auth;

import org.junit.jupiter.api.Test;
import java.util.HashSet;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class CachedUserTest {
    @Test
    void testGettersAndSetters() {
        Set<String> groups = new HashSet<>();
        groups.add("group1");
        CachedUser user = new CachedUser("bob", null, 123L);
        assertEquals("bob", user.getUsername());
        assertNull(user.getGroups());
        assertEquals(123L, user.getTimestamp());
        user.setGroups(groups);
        assertEquals(groups, user.getGroups());
    }

    @Test
    void testSetGroupsTwiceThrows() {
        CachedUser user = new CachedUser("bob");
        user.setGroups(Set.of("g1"));
        Exception ex = assertThrows(IllegalStateException.class, () -> user.setGroups(Set.of("g2")));
        assertTrue(ex.getMessage().contains("Groups can only be set once"));
    }
}
