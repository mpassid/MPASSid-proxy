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

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import org.opensaml.messaging.context.BaseContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * This class is used to store oidc information produced in authentication for
 * webflow to process later.
 */
public class SocialUserOpenIdConnectContext extends BaseContext {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE
     * IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(SocialUserOpenIdConnectContext.class);

    /** Client Id. */
    @Nonnull
    private ClientID clientID;
    
    /** Client Secret. */
    @Nonnull
    private Secret clientSecret;
    
    /** Scope. */
    @Nonnull
    private Scope scope;
    
    /** OIDC Prompt. */
    private Prompt prompt;
    
    /** OIDC Authentication Class Reference values. */
    private List<ACR> acrs;
    
    /** OIDC Display. */
    private Display display;
    
    /** OIDC provider metadata. */
    private OIDCProviderMetadata oIDCProviderMetadata;
   
    /** oidc authentication request */
    private URI authenticationRequestURI;

    /** oidc authentication response URI. */
    private URI authenticationResponseURI;

    /** oidc authentication success response. */
    private AuthenticationSuccessResponse authSuccessResponse;

    /** oidc token response. */
    private OIDCTokenResponse oidcTknResponse;

    /** State parameter. */
    private State state;
    
    /** Redirect URI. */
    private URI redirectURI;

    /**
     * 
     * @return
     */
    public URI getRedirectURI() {
        return redirectURI;
    }

    /**
     * 
     * @param redirectURI
     */
    public void setRedirectURI(URI redirectURI) {
        this.redirectURI = redirectURI;
    }

    /**
     * Getter for Oauth2 client id.
     * 
     * @return
     */
    public ClientID getClientID() {
        return clientID;
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param clientID
     *            Oauth2 Client ID
     */
    public void setClientID(ClientID clientID) {
        this.clientID = clientID;
    }

    
    /**
     * 
     * @param clientSecret
     */
    public void setClientSecret(Secret clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     * 
     * @return
     */
    public Scope getScope() {
        return scope;
    }

    /**
     * 
     * @param scope
     */
    public void setScope(Scope scope) {
        this.scope = scope;
    }

    /**
     * 
     * @return
     */
    public Prompt getPrompt() {
        return prompt;
    }

    /**
     * 
     * @param prompt
     */
    public void setPrompt(Prompt prompt) {
        this.prompt = prompt;
    }

    /**
     * 
     * @return
     */
    public List<ACR> getAcrs() {
        return acrs;
    }

    /**
     * 
     * @param acrs
     */
    public void setAcrs(List<ACR> acrs) {
        this.acrs = acrs;
    }

    /**
     * 
     * @return
     */
    public Display getDisplay() {
        return display;
    }

    /**
     * 
     * @param display
     */
    public void setDisplay(Display display) {
        this.display = display;
    }

    /**
     * 
     * @return
     */
    public OIDCProviderMetadata getoIDCProviderMetadata() {
        return oIDCProviderMetadata;
    }

    /**
     * 
     * @param oIDCProviderMetadata
     */
    public void setoIDCProviderMetadata(OIDCProviderMetadata oIDCProviderMetadata) {
        this.oIDCProviderMetadata = oIDCProviderMetadata;
    }

    /**
     * Returns the oidc authentication request URI to be used for authentication.
     * 
     * @return request URI for authentication
     */
    public URI getAuthenticationRequestURI() {
        log.trace("Entering & Leaving");
        return authenticationRequestURI;
    }

    /**
     * Set the oidc provider request for authentication.
     * 
     * @param request
     *            to be used for authentication
     */
    public void setAuthenticationRequestURI(URI request) {
        log.trace("Entering");
        log.debug("Setting auth request redirect to "+request.toString());
        this.authenticationRequestURI = request;
        log.trace("Leaving");
    }

    /**
     * Returns token response or null.
     * 
     * @return token response
     */
    public OIDCTokenResponse getOidcTokenResponse() {
        log.trace("Entering & Leaving");
        return oidcTknResponse;
    }

    /**
     * Sets token response.
     * 
     * @param oidcTokenResponse
     *            response from provider
     */
    public void setOidcTokenResponse(OIDCTokenResponse oidcTokenResponse) {
        log.trace("Entering");
        this.oidcTknResponse = oidcTokenResponse;
        log.trace("Leaving");
    }

    /**
     * Getter for State parameter.
     * 
     * @return state parameter
     */
    public State getState() {
        return state;
    }

    /**
     * Setter for State parameter.
     * 
     * @param stateParam
     *            parameter
     */
    public void setState(State stateParam) {
        this.state = stateParam;
    }

    /**
     * Returns authentication success response or null.
     * 
     * @return authentication success response.
     */
    public AuthenticationSuccessResponse getAuthenticationSuccessResponse() {
        log.trace("Entering & Leaving");
        return authSuccessResponse;
    }

    /**
     * Sets authentication success response.
     * 
     * @param authenticationSuccessResponse
     *            response from ther provider
     */
    public void setAuthenticationSuccessResponse(
            AuthenticationSuccessResponse authenticationSuccessResponse) {
        log.trace("Entering");
        this.authSuccessResponse = authenticationSuccessResponse;
        log.trace("Leaving");
    }

    /**
     * Returns authentication response URI or null.
     * 
     * @return authentication response URI
     */
    public URI getAuthenticationResponseURI() {
        log.trace("Entering & Leaving");
        return authenticationResponseURI;
    }

    /**
     * Parses authentication response URI from request.
     * 
     * @param authenticationResponseHttpRequest
     *            request
     * 
     * @throws URISyntaxException
     *             if request has malformed URL and/or query parameters
     */
    public void setAuthenticationResponseURI(
            HttpServletRequest authenticationResponseHttpRequest)
            throws URISyntaxException {
        log.trace("Entering");
        String temp = authenticationResponseHttpRequest.getRequestURL() + "?"
                + authenticationResponseHttpRequest.getQueryString();
        this.authenticationResponseURI = new URI(temp);
        log.trace("Leaving");

    }

    /**
     * 
     * @return
     */
    Secret getClientSecret() {
        return clientSecret;
    }
    

}
