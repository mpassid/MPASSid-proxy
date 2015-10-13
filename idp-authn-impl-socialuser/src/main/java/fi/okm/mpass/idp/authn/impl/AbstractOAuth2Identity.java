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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AuthnEventIds;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import fi.okm.mpass.idp.authn.SocialRedirectAuthenticationException;

/** Implements OAuth2/OpenId basics for classes using Nimbus library. */
public abstract class AbstractOAuth2Identity {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(AbstractOAuth2Identity.class);

    /** OIDC Scope. */
    private Scope scope;
    /** OIDC Client Id. */
    private ClientID clientID;
    /** OIDC Client Secret. */
    private Secret clientSecret;
    /** OIDC Authorization Endpoint. */
    private URI authorizationEndpoint;
    /** OIDC Token Endpoint. */
    private URI tokenEndpoint;
    /** OIDC UserInfo Endpoint. */
    private URI userinfoEndpoint;
    /** OIDC Revocation Endpoint. */
    private URI revocationEndpoint;

    /** map of claims to principals. */
    @Nonnull
    private Map<String, String> claimsPrincipals;

    /**
     * Setter for OAuth2 Scope values.
     * 
     * @param oauth2Scopes
     *            OAuth2 Scope values
     */
    public void setScope(List<String> oauth2Scopes) {
        log.trace("Entering");
        scope = new Scope();
        for (String oidcScope : oauth2Scopes) {
            scope.add(oidcScope);
        }
        log.trace("Leaving");
    }

    /**
     * Getter for OAuth2 Scope values.
     * 
     * @return OAuth2 Scope values
     */
    protected Scope getScope() {
        log.trace("Entering");
        if (scope == null) {
            scope = new Scope();
        }
        log.trace("Leaving");
        return scope;
    }

    /**
     * Sets map of claims to principals.
     * 
     * @param oidcClaimsPrincipals
     *            map of claims to principals
     * */
    public void setClaimsPrincipals(Map<String, String> oidcClaimsPrincipals) {
        log.trace("Entering");
        this.claimsPrincipals = oidcClaimsPrincipals;
        log.trace("Leaving");
    }

    /**
     * Gets map of claims to principals.
     * 
     * @return map of claims to principals
     * */
    protected Map<String, String> getClaimsPrincipals() {
        log.trace("Entering & Leaving");
        return claimsPrincipals;
    }

    /**
     * Setter for authorization endpoint.
     * 
     * @param endPoint
     *            OpenId AuthorizationEndpoint
     * @throws URISyntaxException
     */
    public void setAuthorizationEndpoint(String endPoint)
            throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.authorizationEndpoint = new URI(endPoint);
    }

    /**
     * Getter for authorization endpoint.
     * 
     * @return AuthorizationEndpoint
     */
    protected URI getAuthorizationEndpoint() {
        log.trace("Entering & Leaving");
        return authorizationEndpoint;
    }

    /**
     * Setter for OpenId token endpoint.
     * 
     * @param endPoint
     *            OpenId TokenEndpoint
     * @throws URISyntaxException
     */
    public void setTokenEndpoint(String endPoint) throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.tokenEndpoint = new URI(endPoint);
    }

    /**
     * Getter for OpenId token endpoint.
     * 
     * @return TokenEndpoint
     */
    protected URI getTokenEndpoint() throws URISyntaxException {
        log.trace("Entering & Leaving");
        return tokenEndpoint;
    }

    /**
     * Setter for OpenId userinfo endpoint.
     * 
     * @param endPoint
     *            OpenId UserinfoEndpoint
     * @throws URISyntaxException
     */
    public void setUserinfoEndpoint(String endPoint) throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.userinfoEndpoint = new URI(endPoint);
    }

    /**
     * Getter for OpenId userinfo endpoint.
     * 
     * @return OpenId UserinfoEndpoint
     */
    protected URI getUserinfoEndpoint() throws URISyntaxException {
        log.trace("Entering & Leaving");
        return userinfoEndpoint;
    }

    /**
     * Setter for OpenId revocation endpoint.
     * 
     * @param endPoint
     *            OpenId RevocationEndpoint
     * @throws URISyntaxException
     */
    public void setRevocationEndpoint(String endPoint)
            throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.revocationEndpoint = new URI(endPoint);
    }

    /**
     * Getter for OpenId revocation endpoint.
     * 
     * @return OpenId RevocationEndpoint
     */
    protected URI getRevocationEndpoint() {
        log.trace("Entering & Leaving");
        return revocationEndpoint;
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param oauth2ClientId
     *            Oauth2 Client ID
     */
    public void setClientId(String oauth2ClientId) {
        log.trace("Entering & Leaving");
        this.clientID = new ClientID(oauth2ClientId);
    }

    /**
     * Getter for Oauth2 client id.
     * 
     * @return Oauth2 Client ID
     */
    protected ClientID getClientId() {
        log.trace("Entering & Leaving");
        return clientID;
    }

    /**
     * Setter for Oauth2 Client secret.
     * 
     * @param oauth2ClientSecret
     *            Oauth2 Client Secret
     */
    public void setClientSecret(String oauth2ClientSecret) {
        log.trace("Entering & Leaving");
        this.clientSecret = new Secret(oauth2ClientSecret);
    }

    /**
     * Getter for Oauth2 Client secret.
     * 
     * @return Oauth2 Client Secret
     */
    protected Secret getClientSecret() {
        log.trace("Entering & Leaving");
        return clientSecret;
    }

    protected TokenRequest getTokenRequest(HttpServletRequest httpRequest)
            throws SocialRedirectAuthenticationException {
        log.trace("Entering");
        try {
            AuthenticationResponse response = null;
            String temp = httpRequest.getRequestURL() + "?"
                    + httpRequest.getQueryString();
            URI uri = new URI(temp);
            response = AuthenticationResponseParser.parse(uri);
            if (!response.indicatesSuccess()) {
                log.trace("Leaving");
                AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) response;
                String error = errorResponse.getErrorObject().getCode();
                String errorDescription = errorResponse.getErrorObject()
                        .getDescription();
                if (errorDescription != null && !errorDescription.isEmpty()) {
                    error += " : " + errorDescription;
                }
                log.trace("Leaving");
                throw new SocialRedirectAuthenticationException(error,
                        AuthnEventIds.AUTHN_EXCEPTION);
            }
            AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;
            AuthorizationCode code = successResponse.getAuthorizationCode();
            URI callback = new URI(httpRequest.getRequestURL().toString());
            AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code,
                    callback);
            ClientAuthentication clientAuth = new ClientSecretBasic(
                    getClientId(), getClientSecret());
            TokenRequest request = new TokenRequest(getTokenEndpoint(),
                    clientAuth, codeGrant);
            State state = (State) httpRequest.getSession().getAttribute(
                    "fi.okm.mpass.state");
            if (state == null || !state.equals(successResponse.getState())) {
                throw new SocialRedirectAuthenticationException(
                        "State parameter not satisfied",
                        AuthnEventIds.AUTHN_EXCEPTION);
            }
            return request;
        } catch (IllegalArgumentException e) {
            log.debug("User is not authenticated yet");
            log.trace("Leaving");
            return null;

        } catch (URISyntaxException | ParseException e) {
            e.printStackTrace();
            log.trace("Leaving");
            throw new SocialRedirectAuthenticationException(e.getMessage(),
                    AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

}
