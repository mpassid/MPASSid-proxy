/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.okm.mpass.idp.authn.impl;

import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.http.core.ContainerSocketProcessor;
import org.simpleframework.transport.SocketProcessor;
import org.simpleframework.transport.connect.Connection;
import org.simpleframework.transport.connect.SocketConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.State;

import fi.okm.mpass.idp.authn.SocialUserAuthenticationException;

/**
 * Unit tests for {@link YleIdentity}.
 */
public class YleIdentityTest {
    
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(YleIdentityTest.class);
    
    /** Yle App Identifier. */
    private String appId;
    
    /** Yle App Key. */
    private String appKey;
    
    /** Client identifier. */
    private String clientId;
    
    /** Client secret. */
    private String clientSecret;
    
    /** The token endpoint for local testing. */
    private String tokenEndpoint;
    
    /** The user info endpoint for local testing. */
    private String userInfoEndpoint;
    
    /** The user claim key. */
    private String userClaim;
    
    /** The error code. */
    private String errorCode;
    
    /** The error description. */
    private String errorDescription;
    
    /**
     * Set up tests.
     */
    @BeforeMethod
    public void setUp() {
        appId = "mockAppId";
        appKey = "mockAppKey";
        clientId = "mockClientId";
        clientSecret = "mockClientSecret";
        final String urlPrefix = "http://localhost:" + SetOIDCInformationTest.CONTAINER_PORT;
        tokenEndpoint = urlPrefix + "/token";
        userInfoEndpoint = urlPrefix + "/userinfo";
        userClaim = "user_key";
        errorCode = "access_denied";
        errorDescription = "mock description";
    }

    /**
     * Runs getRedirectUrl with null {@link HttpServletRequest}.
     * @throws Exception
     */
    @Test public void testRedirectNullRequest() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        Assert.assertNull(yleId.getRedirectUrl(null));
    }

    /**
     * Runs getRedirectUrl with empty {@link HttpServletRequest}.
     * @throws Exception
     */
    @Test public void testRedirectNoAuthzEndpoint() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setRequestURI("/mock/");
        Assert.assertNull(yleId.getRedirectUrl(httpRequest));
    }

    /**
     * Runs getRedirectUrl with prerequisites fulfilled.
     * @throws Exception
     */
    @Test public void testRedirect() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        final String authzEndpoint = "http://mock.org/authorize";
        yleId.setAuthorizationEndpoint(authzEndpoint);
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setRequestURI("/mock/");
        final String redirectUrl = yleId.getRedirectUrl(httpRequest);
        Assert.assertNotNull(redirectUrl);
        Assert.assertTrue(redirectUrl.startsWith(authzEndpoint));
        Assert.assertTrue(redirectUrl.contains("app_id=" + appId));
        Assert.assertTrue(redirectUrl.contains("app_key=" + appKey));
        Assert.assertTrue(redirectUrl.contains("client_id=" + clientId));
    }

    /**
     * Runs getSubject with empty {@link HttpServletRequest}.
     * @throws Exception
     */
    @Test public void testSubjectEmptyRequest() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        Assert.assertNull(yleId.getSubject(new MockHttpServletRequest()));
    }

    /**
     * Runs getSubject with error token response.
     * @throws Exception
     */
    @Test public void testSubjectErrorToken() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        yleId.setClientSecret(clientSecret);
        final String urlPrefix = "http://localhost:" + SetOIDCInformationTest.CONTAINER_PORT;
        final String tokenEndpoint = urlPrefix + "/errorToken";
        yleId.setTokenEndpoint(tokenEndpoint);
        yleId.setUserinfoEndpoint(userInfoEndpoint);
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setQueryString("code=mockCode&state=mockState");
        httpRequest.getSession(true).setAttribute(AbstractOAuth2Identity.SESSION_ATTR_STATE, new State("mockState"));
        String exception = null;
        try {
            executeGetSubjectWithServer(yleId, httpRequest);
        } catch (SocialUserAuthenticationException e) {
            exception = e.getMessage();
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.startsWith(errorCode));
        Assert.assertTrue(exception.contains(errorDescription));
    }

    
    /**
     * Runs getSubject with prerequisites fulfilled.
     * @throws Exception
     */
    @Test public void testSubjectSuccess() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        yleId.setClientSecret(clientSecret);
        yleId.setTokenEndpoint(tokenEndpoint);
        yleId.setUserinfoEndpoint(userInfoEndpoint);
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setQueryString("code=mockCode&state=mockState");
        httpRequest.getSession(true).setAttribute(AbstractOAuth2Identity.SESSION_ATTR_STATE, new State("mockState"));
        final Subject subject = executeGetSubjectWithServer(yleId, httpRequest);
        Assert.assertNotNull(subject);
        Assert.assertEquals(subject.getPrincipals().iterator().next().getName(), "mockUser");
    }
    
    /**
     * Executes the getSubject method with simple container running.
     * @param yleId
     * @param httpRequest
     * @return
     * @throws Exception
     */
    protected Subject executeGetSubjectWithServer(final YleIdentity yleId, final HttpServletRequest httpRequest) throws Exception {
        final Container container = new SimpleContainer();
        final SocketProcessor server = new ContainerSocketProcessor(container);
        final Connection connection = new SocketConnection(server);
        final SocketAddress address = new InetSocketAddress(SetOIDCInformationTest.CONTAINER_PORT);
        connection.connect(address);
        try {
            return yleId.getSubject(httpRequest);
        } catch (Exception e) {
            throw e;
        } finally {
            connection.close();
        }
    }
    
    /**
     * Initializes {@link YleIdentity} with default settings.
     * @return
     */
    protected YleIdentity initYleIdentity() {
        final YleIdentity yleId = new YleIdentity();
        yleId.setAppId(appId);
        yleId.setAppKey(appKey);
        yleId.setClientId(clientId);
        final Map<String, String> claims = new HashMap<>();
        claims.put(userClaim, "userId");
        yleId.setClaimsPrincipals(claims);
        return yleId;
    }
    
    /**
     * Simple container implementation.
     */
    class SimpleContainer implements Container {
        
        /**
         * Constructor.
         */
        public SimpleContainer() {
        }

        @Override
        /** {@inheritDoc} */
        public void handle(Request request, Response response) {
            log.trace("Server got request for {}", request.getTarget());
            try {
                response.setContentType("application/json");
                String output = "";
                if (request.getTarget().contains("/token")) {
                    output = "{ \"access_token\":\"2YotnFZFEjr1zCsicMWpAA\", \"token_type\":\"Bearer\", \"expires_in\":3600 }";
                } else if (request.getTarget().contains("/userinfo")) {
                    output = "{ \"" + userClaim + "\":\"mockUser\" }";
                } else if (request.getTarget().contains("/errorToken")) {
                    output = "{ \"error\":\"" + errorCode + "\", \"error_description\":\"" + errorDescription + "\" }";
                    response.setCode(500);
                }
                IOUtils.copy(new StringReader(output), response.getOutputStream());
                response.getOutputStream().close();
             } catch(Exception e) {
                 log.error("Container-side exception ", e);
             }  
        }
    }
}
