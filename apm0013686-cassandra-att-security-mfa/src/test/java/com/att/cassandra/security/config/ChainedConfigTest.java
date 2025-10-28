package com.att.cassandra.security.config;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ChainedConfigTest {
    @Test
    void testGettersAndSetters() {
        ChainedConfig config = new ChainedConfig();
        List<String> authenticators = Arrays.asList("ldap", "jwt");
        List<String> authorizers = Arrays.asList("ldap", "cassandra");
        config.setAuthenticators(authenticators);
        config.setAuthorizers(authorizers);
        assertSame(authenticators, config.getAuthenticators());
        assertSame(authorizers, config.getAuthorizers());
    }
}
