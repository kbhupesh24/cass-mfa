package com.att.cassandra.security.config;

public class JwtConfig {
    private String userInfoUrl;
    private long refreshMinutes = 15;
    private long expireHours = 24;

    public String getUserInfoUrl() { return userInfoUrl; }
    public void setUserInfoUrl(String userInfoUrl) { this.userInfoUrl = userInfoUrl; }

    public long getRefreshMinutes() { return refreshMinutes; }
    public void setRefreshMinutes(long refreshMinutes) { this.refreshMinutes = refreshMinutes; }

    public long getExpireHours() { return expireHours; }
    public void setExpireHours(long expireHours) { this.expireHours = expireHours; }
}
