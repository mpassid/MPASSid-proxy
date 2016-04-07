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

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import org.opensaml.messaging.context.BaseContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

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

    /** oidc methods and parameters. */
    private OpenIdConnectIdentity oidc;

    /** oidc authentication response URI. */
    private URI authenticationRequestURI;

    /** oidc authentication response URI. */
    private URI authenticationResponseURI;

    /** oidc authentication success response. */
    private AuthenticationSuccessResponse authSuccessResponse;

    /** oidc token response. */
    private OIDCTokenResponse oidcTknResponse;

    /** State parameter. */
    private State state;

    /**
     * Returns the oidc provider URI to be used for authentication.
     * 
     * @return URI for authentication
     */
    public URI getAuthenticationRequestURI() {
        log.trace("Entering & Leaving");
        return authenticationRequestURI;
    }

    /**
     * Set the oidc provider URI for authentication.
     * 
     * @param requestURI
     *            to be used for authentication
     */
    public void setAuthenticationRequestURI(URI requestURI) {
        log.trace("Entering");
        this.authenticationRequestURI = requestURI;
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
     * Method for setting the openid connect parameters.
     * 
     * @param openIdConnectIdentity
     *            openidconnect parameters
     */

    public void setOpenIdConnectInformation(
            @Nonnull OpenIdConnectIdentity openIdConnectIdentity) {
        log.trace("Entering");
        this.oidc = openIdConnectIdentity;
        log.trace("Leaving");
    }

    /**
     * Method returns oidc functionality.
     * 
     * @return oidc methods and paramaters
     */

    public OpenIdConnectIdentity getOpenIdConnectInformation() {
        log.trace("Entering & Leaving");
        return this.oidc;
    }

}
