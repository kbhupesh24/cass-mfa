package com.att.cassandra.security.config;

public class LdapConfig {
    private String url;
    @Deprecated
    private String userDnPattern;
    private String bindUser;
    private String bindPassword;
    private String groupBaseDn;
    private String groupAttribute;
    private boolean trustAllCerts = false;
    private String groupObjectClass;
    private String userAttribute;
    private String userBaseDn;
    private String groupMemberAttribute;

    // getters and setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getUserDnPattern() { return userDnPattern; }
    public void setUserDnPattern(String userDnPattern) { this.userDnPattern = userDnPattern; }
    public String getBindUser() { return bindUser; }
    public void setBindUser(String bindUser) { this.bindUser = bindUser; }
    public String getBindPassword() { return bindPassword; }
    public void setBindPassword(String bindPassword) { this.bindPassword = bindPassword; }
    public String getGroupBaseDn() { return groupBaseDn; }
    public void setGroupBaseDn(String groupBaseDn) { this.groupBaseDn = groupBaseDn; }
    public String getGroupAttribute() { return groupAttribute; }
    public void setGroupAttribute(String groupAttribute) { this.groupAttribute = groupAttribute; }
    public boolean isTrustAllCerts() { return trustAllCerts; }
    public void setTrustAllCerts(boolean trustAllCerts) { this.trustAllCerts = trustAllCerts; }
    public String getGroupObjectClass() { return groupObjectClass; }
    public void setGroupObjectClass(String groupObjectClass) { this.groupObjectClass = groupObjectClass; }
    public String getUserAttribute() { return userAttribute; }
    public void setUserAttribute(String userAttribute) { this.userAttribute = userAttribute; }
    public String getUserBaseDn() { return userBaseDn; }
    public void setUserBaseDn(String userBaseDn) { this.userBaseDn = userBaseDn; }
    public String getGroupMemberAttribute() { return groupMemberAttribute; }
    public void setGroupMemberAttribute(String groupMemberAttribute) { this.groupMemberAttribute = groupMemberAttribute; }
}
