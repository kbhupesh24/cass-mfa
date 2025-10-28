package com.att.cassandra.security.config;

import java.util.List;

/**
 * Config section for chained authenticators and authorizers.
 *
 * chained:
 *   authenticators: [ldap, jwt, password]
 *   authorizers: [ldap, jwt, cassandra]
 *
 * The names must match keys in the top-level authenticators/authorizers maps.
 */
public class ChainedConfig {
    private List<String> authenticators;
    private List<String> authorizers;

    public List<String> getAuthenticators() { return authenticators; }
    public void setAuthenticators(List<String> authenticators) { this.authenticators = authenticators; }

    public List<String> getAuthorizers() { return authorizers; }
    public void setAuthorizers(List<String> authorizers) { this.authorizers = authorizers; }
}
