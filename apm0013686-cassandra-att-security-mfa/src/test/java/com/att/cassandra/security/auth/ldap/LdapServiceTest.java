package com.att.cassandra.security.auth.ldap;

import com.att.cassandra.security.config.CacheConfig;
import com.att.cassandra.security.config.ConfigLoader;
import com.att.cassandra.security.config.LdapConfig;
import com.att.cassandra.security.config.SecurityConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import com.unboundid.util.ssl.SSLUtil;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class LdapServiceTest {
    @BeforeEach
    void clearState() throws Exception {
        LdapService.clearTestConfig();
        Field f = LdapService.class.getDeclaredField("instances");
        f.setAccessible(true);
        ((Map<?, ?>) f.get(null)).clear();
    }

    @AfterEach
    void cleanup() {
        LdapService.clearTestConfig();
    }

    @Test
    void testGetInstance_cacheHitSkipsLoad() throws Exception {
        // pre-populate
        LdapService dummy = new LdapService(new LdapConfig());
        Field f = LdapService.class.getDeclaredField("instances");
        f.setAccessible(true);
        ((Map<String, LdapService>) f.get(null)).put("foo", dummy);
        try (MockedStatic<ConfigLoader> mockCfg = mockStatic(ConfigLoader.class)) {
            mockCfg.when(ConfigLoader::load).thenThrow(new AssertionError("should not load"));
            LdapService result = LdapService.getInstance("foo");
            assertSame(dummy, result);
        }
    }

    @Test
    void testGetInstance_missingConfig() {
        SecurityConfig sc = new SecurityConfig();
        sc.setCache(new CacheConfig());
        sc.setExternalServices(null);
        try (MockedStatic<ConfigLoader> mockCfg = mockStatic(ConfigLoader.class)) {
            mockCfg.when(ConfigLoader::load).thenReturn(sc);
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> LdapService.getInstance("bar"));
            assertTrue(ex.getMessage().contains("No external_service config"));
        }
    }

    @Test
    void testGetInstance_happyPath() {
        SecurityConfig sc = new SecurityConfig();
        CacheConfig cc = new CacheConfig(); cc.setTtlSeconds(1); cc.setCleanupAfterSeconds(1);
        sc.setCache(cc);
        Map<String, Object> svcConf = new HashMap<>();
        svcConf.put("url", "ldap://loc");
        svcConf.put("bindUser", "u");
        svcConf.put("bindPassword", "p");
        svcConf.put("userAttribute", "uid");
        svcConf.put("userBaseDn", "bd");
        svcConf.put("groupBaseDn", "gd");
        svcConf.put("groupAttribute", "cn");
        sc.setExternalServices(Map.of("foo", svcConf));
        try (MockedStatic<ConfigLoader> mockCfg = mockStatic(ConfigLoader.class)) {
            mockCfg.when(ConfigLoader::load).thenReturn(sc);
            LdapService svc1 = LdapService.getInstance("foo");
            assertNotNull(svc1.getCache());
            LdapService svc2 = LdapService.getInstance("foo");
            assertSame(svc1, svc2);
        }
    }

    @Test
    void testFindUserDn_nullGuard() throws Exception {
        // config null or missing params
        assertNull(new LdapService(null).findUserDn("u"));
        assertNull(new LdapService(new LdapConfig()).findUserDn(null));
    }

    @Test
    void testFindUserDn_emptyEntries() throws Exception {
        LdapConfig cfg = new LdapConfig();
        cfg.setUrl("ldap://loc"); cfg.setBindUser("u"); cfg.setBindPassword("p");
        cfg.setUserBaseDn("bd"); cfg.setUserAttribute("uid");
        LdapService svc = new LdapService(cfg);
        try (MockedConstruction<LDAPConnection> mc = mockConstruction(LDAPConnection.class, (conn, ctx) -> {
            SearchResult empty = mock(SearchResult.class);
            when(empty.getSearchEntries()).thenReturn(List.of());
            when(conn.search(any(SearchRequest.class))).thenReturn(empty);
        })) {
            assertNull(svc.findUserDn("bob"));
        }
    }

    @Test
    void testFindUserDn_successAndTrustAll() throws Exception {
        for (boolean trust: List.of(false, true)) {
            LdapConfig cfg = new LdapConfig();
            cfg.setUrl("ldap://loc"); cfg.setBindUser("u"); cfg.setBindPassword("p");
            cfg.setUserBaseDn("bd"); cfg.setUserAttribute("uid");
            cfg.setTrustAllCerts(trust);
            LdapService svc = new LdapService(cfg);
            try (MockedConstruction<LDAPConnection> mc = mockConstruction(LDAPConnection.class, (conn, ctx) -> {
                SearchResultEntry e = mock(SearchResultEntry.class);
                when(e.getDN()).thenReturn("uid=b,bd");
                SearchResult res = mock(SearchResult.class);
                when(res.getSearchEntries()).thenReturn(List.of(e));
                when(conn.search(any(SearchRequest.class))).thenReturn(res);
            })) {
                assertEquals("uid=b,bd", svc.findUserDn("bob"));
            }
        }
    }

    @Test
    void testFindUserDn_exceptionWrap() throws Exception {
        LdapConfig cfg = new LdapConfig();
        cfg.setUrl("ldap://loc"); cfg.setBindUser("u"); cfg.setBindPassword("p");
        cfg.setUserBaseDn("bd"); cfg.setUserAttribute("uid");
        // exception via SSLUtil failing
        cfg.setTrustAllCerts(true);
        LdapService svc = new LdapService(cfg);
        try (MockedConstruction<SSLUtil> mc = mockConstruction(SSLUtil.class, (ssl, ctx) -> {
            when(ssl.createSSLSocketFactory()).thenThrow(new GeneralSecurityException("fail"));
        })) {
            LDAPException ex = assertThrows(LDAPException.class, () -> svc.findUserDn("bob"));
            assertEquals(ResultCode.CONNECT_ERROR, ex.getResultCode());
        }
    }

    @Test
    void testAuthenticateBind_branches() throws Exception {
        LdapConfig cfg = new LdapConfig();
        cfg.setUrl("ldap://loc"); cfg.setBindUser("u"); cfg.setBindPassword("p");
        cfg.setUserBaseDn("bd"); cfg.setUserAttribute("uid");
        LdapService svc = new LdapService(cfg);
        // nulls
        assertFalse(svc.authenticateBind(null, "pw"));
        assertFalse(svc.authenticateBind("u", null));
        // findUserDn throws
        LdapService spy1 = spy(svc);
        doThrow(new LDAPException(ResultCode.CONNECT_ERROR)).when(spy1).findUserDn("bob");
        assertFalse(spy1.authenticateBind("bob","pw"));
        // userDn null
        LdapService spy2 = spy(svc);
        doReturn(null).when(spy2).findUserDn("bob");
        assertFalse(spy2.authenticateBind("bob","pw"));
        // success
        LdapService spy3 = spy(svc);
        doReturn("dn").when(spy3).findUserDn("bob");
        try (MockedConstruction<LDAPConnection> mc = mockConstruction(LDAPConnection.class)) {
            assertTrue(spy3.authenticateBind("bob","pw"));
        }
        // bind exception: real connection attempt will fail and return false
        LdapService spy4 = spy(svc);
        doReturn("dn").when(spy4).findUserDn("bob");
        assertFalse(spy4.authenticateBind("bob","pw"));
    }

    @Test
    void testFetchUserGroups_branches() throws Exception {
        LdapConfig cfg = new LdapConfig();
        cfg.setUrl("ldap://loc"); cfg.setBindUser("u"); cfg.setBindPassword("p");
        cfg.setUserBaseDn("bd"); cfg.setUserAttribute("uid");
        cfg.setGroupBaseDn("gb"); cfg.setGroupAttribute("cn");
        LdapService svc = new LdapService(cfg);
        // null/empty username
        assertThrows(IllegalArgumentException.class, ()->svc.fetchUserGroups(null));
        assertThrows(IllegalArgumentException.class, ()->svc.fetchUserGroups(""));
        // userDn null
        LdapService spy1 = spy(svc);
        doReturn(null).when(spy1).findUserDn("bob");
        assertTrue(spy1.fetchUserGroups("bob").isEmpty());
        // no groups
        LdapService spy2 = spy(svc);
        doReturn("dn").when(spy2).findUserDn("bob");
        try (MockedConstruction<LDAPConnection> mc = mockConstruction(LDAPConnection.class, (conn, ctx)->{
            SearchResult r = mock(SearchResult.class);
            when(r.getSearchEntries()).thenReturn(List.of());
            when(conn.search(any(SearchRequest.class))).thenReturn(r);
        })) {
            assertTrue(spy2.fetchUserGroups("bob").isEmpty());
        }
        // one group
        LdapService spy3 = spy(svc);
        doReturn("dn").when(spy3).findUserDn("bob");
        try (MockedConstruction<LDAPConnection> mc = mockConstruction(LDAPConnection.class, (conn, ctx)->{
            SearchResultEntry e = mock(SearchResultEntry.class);
            when(e.getAttributeValue("cn")).thenReturn("grp");
            SearchResult r = mock(SearchResult.class);
            when(r.getSearchEntries()).thenReturn(List.of(e));
            when(conn.search(any(SearchRequest.class))).thenReturn(r);
        })) {
            assertEquals(Set.of("grp"), spy3.fetchUserGroups("bob"));
        }
        // exception via SSLUtil failing
        LdapConfig cfgEx = new LdapConfig();
        cfgEx.setUrl("ldap://loc"); cfgEx.setBindUser("u"); cfgEx.setBindPassword("p");
        cfgEx.setUserBaseDn("bd"); cfgEx.setUserAttribute("uid");
        cfgEx.setGroupBaseDn("gb"); cfgEx.setGroupAttribute("cn");
        cfgEx.setTrustAllCerts(true);
        LdapService svcEx = new LdapService(cfgEx);
        LdapService spyEx = spy(svcEx);
        doReturn("dn").when(spyEx).findUserDn("bob");
        try (MockedConstruction<SSLUtil> mc = mockConstruction(SSLUtil.class, (ssl, ctx) -> {
            when(ssl.createSSLSocketFactory()).thenThrow(new GeneralSecurityException("fail"));
        })) {
            assertThrows(LDAPException.class, () -> spyEx.fetchUserGroups("bob"));
        }
    }
}
