package com.att.cassandra.security.auth.jwt;

/**
 * Holds the JWT token for the current authentication request.
 */
public class JwtTokenContext {
    private static final ThreadLocal<String> TOKEN = new ThreadLocal<>();

    public static void setToken(String token) {
        TOKEN.set(token);
    }

    public static String getToken() {
        return TOKEN.get();
    }

    public static void clear() {
        TOKEN.remove();
    }
}
