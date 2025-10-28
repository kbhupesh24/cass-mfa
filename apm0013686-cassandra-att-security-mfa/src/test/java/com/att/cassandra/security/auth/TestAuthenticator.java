package com.att.cassandra.security.auth;

import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.exceptions.AuthenticationException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class TestAuthenticator implements IAuthenticator, ChainedAuthenticator.SupportsCredentialType {
    public TestAuthenticator(String logicalName) { }
    @Override public void validateConfiguration() {}
    @Override public void setup() {}
    @Override public SaslNegotiator newSaslNegotiator(InetAddress clientAddress) {
        return new SaslNegotiator() {
            private boolean complete = false;
            @Override public byte[] evaluateResponse(byte[] clientResponse) { complete = true; return null; }
            @Override public boolean isComplete() { return complete; }
            @Override public AuthenticatedUser getAuthenticatedUser() { return new AuthenticatedUser("test"); }
        };
    }
    @Override public boolean requireAuthentication() { return true; }
    @Override public Set<? extends org.apache.cassandra.auth.DataResource> protectedResources() { return Collections.emptySet(); }
    @Override public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException { return new AuthenticatedUser("test"); }
    @Override public boolean supports(byte[] initialSaslPayload) { return true; }
}
