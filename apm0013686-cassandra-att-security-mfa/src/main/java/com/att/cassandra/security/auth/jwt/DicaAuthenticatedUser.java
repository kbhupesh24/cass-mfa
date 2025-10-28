package com.att.cassandra.security.auth.jwt;

import com.google.common.base.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author kb402n
 */
public class DicaAuthenticatedUser extends org.apache.cassandra.auth.AuthenticatedUser {
    private static final Logger logger = LoggerFactory.getLogger(DicaAuthenticatedUser.class);
    private final String realm;
    private final String userName;
    private final String jwtToken;
    private boolean isAnnonymous;
    private boolean isSuper;


    public DicaAuthenticatedUser(String name, String jwtToken, String realm) {
        super(name);
        this.realm = realm;
        this.userName = name;
        this.jwtToken = jwtToken;
        this.isAnnonymous = true;
        this.isSuper = true;
        // TODO - Set Groups and Roles
    }

    public String getRealm() {
        return realm;
    }

    public boolean isSuper() {
        return isSuper;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setSuper(boolean isSuper) {
        this.isSuper = isSuper;
    }

    public boolean isAnonymous() {
        return isAnnonymous;
    }



    public void setAnonymous(boolean isAnnonymous) {
        this.isAnnonymous = isAnnonymous;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;

        if (!(o instanceof DicaAuthenticatedUser))
            return false;

        DicaAuthenticatedUser u = (DicaAuthenticatedUser) o;
        return Objects.equal(userName, u.userName);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(userName);
    }
}