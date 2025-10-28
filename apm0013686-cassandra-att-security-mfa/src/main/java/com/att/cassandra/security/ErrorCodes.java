package com.att.cassandra.security;

/**
 * Centralized error, warning, and info codes for logging and exceptions.
 * Update this file and the wiki when adding new codes.
 */
public final class ErrorCodes {
    // Error codes (Exxx)
    public static final String E102 = "E102"; // security.yaml not found
    public static final String E103 = "E103"; // Failed to load configuration
    public static final String E104 = "E104"; // Groups can only be set once
    public static final String E106 = "E106"; // No authnId
    public static final String E107 = "E107"; // SASL not complete
    public static final String E108 = "E108"; // Config validation errors (mode/auth/roles)
    public static final String E109 = "E109"; // Unknown authorization mode
    public static final String E110 = "E110"; // Unsupported operation in authorizer
    public static final String E111 = "E111"; // LoginException (JWT/LDAP)

    // Warning codes (Wxxx)
    public static final String W201 = "W201"; // User has no groups in LDAP
    public static final String W202 = "W202"; // Failed to fetch groups for user
    public static final String W203 = "W203"; // UserInfo endpoint returned non-200
    public static final String W204 = "W204"; // Error calling UserInfo endpoint

    // Info codes (Ixxx)
    // (none needed for JAAS/login.conf)

    private ErrorCodes() {}
}
