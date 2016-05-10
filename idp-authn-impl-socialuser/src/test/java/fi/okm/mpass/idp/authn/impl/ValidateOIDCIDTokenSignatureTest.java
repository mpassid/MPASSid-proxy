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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import javax.annotation.Nonnull;

import org.apache.commons.io.IOUtils;
import org.mockito.Mockito;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.http.core.ContainerSocketProcessor;
import org.simpleframework.transport.SocketProcessor;
import org.simpleframework.transport.connect.Connection;
import org.simpleframework.transport.connect.SocketConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenSignature}.
 */
public class ValidateOIDCIDTokenSignatureTest extends AbstractOIDCIDTokenTest {
    
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(ValidateOIDCIDTokenSignatureTest.class);
    
    /** Action to be tested. */
    private ValidateOIDCIDTokenSignature action;
    
    /** {@inheritDoc} */
    @Override
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }
    
    /** {@inheritDoc} */
    @BeforeMethod public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenSignature();
    }
    
    
    /**
     * Tests with invalid JWK uri.
     */
    @Test public void testInvalidJwkUri() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(getOidcProviderMetadata());
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests with invalid JWK contents.
     */
    @Test public void testInvalidJwkContents() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(initializeMockMetadata());
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = executeWithServer(action, null, null);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests with empty JWK contents.
     */
    @Test public void testEmptyJwkContents() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(initializeMockMetadata());
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = executeWithServer(action, "empty-jwk", null);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests with unsupported (alg/use) JWK contents.
     */
    @Test public void testUnsupportedJwkContents() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(initializeMockMetadata());
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = executeWithServer(action, "mock-jwk2", null);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }
    
    /**
     * Tests with plain (unsigned) token.
     */
    @Test public void testUnsignedToken() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(initializeMockMetadata());
        suCtx.setOidcTokenResponse(getOidcTokenResponse(DEFAULT_ISSUER));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = executeWithServer(action, "mock-jwk", null);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }
    
    /**
     * Tests with invalid signature (wrong key).
     */
    @Test public void testInvalidSignatureToken() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(initializeMockMetadata());
        
        final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);

        final RSAPrivateKey privateKey = (RSAPrivateKey) keyGenerator.genKeyPair().getPrivate();
        
        final JWTClaimsSet claimsSet = buildClaimsSet(null, DEFAULT_ISSUER, null);

        final SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        final AccessToken accessToken = new BearerAccessToken();
        final RefreshToken refreshToken = new RefreshToken();
        final JWSSigner signer = new RSASSASigner(privateKey);
        signedJwt.sign(signer);
        final OIDCTokens oidcTokens = new OIDCTokens(signedJwt, accessToken, refreshToken);
        final OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(oidcTokens);

        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        
        final Event event = executeWithServer(action, "mock-jwk", null);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests with valid signature.
     */
    @Test public void testValidSignatureToken() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setoIDCProviderMetadata(initializeMockMetadata());
        
        final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);

        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        final JWTClaimsSet claimsSet = buildClaimsSet(null, DEFAULT_ISSUER, null);

        final SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        final AccessToken accessToken = new BearerAccessToken();
        final RefreshToken refreshToken = new RefreshToken();
        final JWSSigner signer = new RSASSASigner(privateKey);
        signedJwt.sign(signer);
        final OIDCTokens oidcTokens = new OIDCTokens(signedJwt, accessToken, refreshToken);
        final OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(oidcTokens);

        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final RSAKey rsaKey = new RSAKey((RSAPublicKey)keyPair.getPublic(), KeyUse.SIGNATURE, null, new Algorithm("RS256"), "mock", 
                new URI("https://mock"), new Base64URL(""), new ArrayList<Base64>());
        final Event event = executeWithServer(action, null, rsaKey);
        Assert.assertNull(event);
    }

    protected static OIDCProviderMetadata initializeMockMetadata() throws Exception {
        final OIDCProviderMetadata oidcMetadata = Mockito.mock(OIDCProviderMetadata.class);
        Mockito.when(oidcMetadata.getJWKSetURI()).thenReturn(new URI("http://localhost:" + SetOIDCInformationTest.CONTAINER_PORT + "/"));
        return oidcMetadata;
    }

    public void testUnparseable() throws Exception {
        // no op
    }
    
    /**
     * Reads the metadata configuration.
     */
    public static OIDCProviderMetadata getOidcProviderMetadata()
            throws Exception {
        InputStream stream = new FileInputStream("src/test/resources/openid-configuration");
        String providerInfo = null;
        try (java.util.Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        } finally {
            stream.close();
        }
        return OIDCProviderMetadata.parse(providerInfo);
    }
    
    /**
     * Executes the action with JWK server turned on.
     * @param action
     * @param filename
     * @param rsaKey
     * @return
     * @throws Exception
     */
    protected Event executeWithServer(final ValidateOIDCIDTokenSignature action, final String filename, final RSAKey rsaKey) throws Exception {
        final Container container = new SimpleContainer(filename, rsaKey);
        final SocketProcessor server = new ContainerSocketProcessor(container);
        final Connection connection = new SocketConnection(server);
        final SocketAddress address = new InetSocketAddress(SetOIDCInformationTest.CONTAINER_PORT);
        connection.connect(address);
        try {
            return action.execute(src);
        } catch (Exception e) {
            throw e;
        } finally {
            connection.close();
        }
    }

    /**
     * Simple container implementation.
     */
    class SimpleContainer implements Container {
        
        /** The file to publish. */
        private final String filename;
        
        /** The key to publish. */
        private final RSAKey rsaKey;
        
        /**
         * Constructor.
         */
        public SimpleContainer(final String file, final RSAKey key) {
            filename = file;
            rsaKey = key;
        }

        @Override
        /** {@inheritDoc} */
        public void handle(Request request, Response response) {
            log.trace("Server got request for {}", request.getTarget());
            try {
                if (rsaKey != null) {
                    final String prefix = "{ \"keys\": [";
                    final String postfix = "] }";
                    final String json = prefix + rsaKey.toJSONString() + postfix;
                    log.debug("Streaming the RSAKey {}", json);
                    IOUtils.copy(new StringReader(json), response.getOutputStream());
                } else {
                    if (filename != null) {
                        final File file = new File("src/test/resources/" + filename);
                        if (file.exists()) {
                            log.debug("Streaming file {}", file.getAbsolutePath());
                            IOUtils.copy(new FileInputStream(file), response.getOutputStream());
                        } else {
                            log.debug("File not found: {}", file.getAbsolutePath());
                        }
                    }
                }
                response.getOutputStream().close();
             } catch(Exception e) {
                 log.error("Container-side exception ", e);
             }  
        }
    }
}
