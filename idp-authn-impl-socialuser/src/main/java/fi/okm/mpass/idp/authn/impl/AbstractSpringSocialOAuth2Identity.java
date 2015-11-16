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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.social.oauth2.GrantType;
import org.springframework.social.oauth2.OAuth2Operations;
import org.springframework.social.oauth2.OAuth2Parameters;
import org.springframework.web.client.HttpClientErrorException;

import fi.okm.mpass.idp.authn.SocialUserAuthenticationException;
import fi.okm.mpass.idp.authn.SocialUserErrorIds;

/** Implements methods common to Oauth2 types. */
public abstract class AbstractSpringSocialOAuth2Identity extends
        AbstractIdentity {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(AbstractSpringSocialOAuth2Identity.class);

    /** Oauth2 Application id. */
    @Nonnull
    private String appId;
    /** Oauth2 Application secret. */
    @Nonnull
    private String appSecret;
    /** Oauth2 methods. */
    private OAuth2Operations oauthOperations;
    /** scope parameter. */
    @Nullable
    private String scope;

    /**
     * Setter for Oauth2 operations.
     * 
     * @param operations
     *            Oauth2 operations
     */
    public void setOauthOperations(OAuth2Operations operations) {
        log.trace("Entering & Leaving");
        this.oauthOperations = operations;
    }

    /**
     * Setter for Oauth2 state.
     * 
     * @param oauth2Scope
     *            Oauth2 state
     */
    public void setScope(String oauth2Scope) {
        log.trace("Entering & Leaving");
        this.scope = oauth2Scope;
    }

    /**
     * Setter for Oauth2 appication id.
     * 
     * @param oauth2AppId
     *            Oauth2 Application ID
     */
    public void setAppId(String oauth2AppId) {
        log.trace("Entering & Leaving");
        this.appId = oauth2AppId;
    }

    /**
     * Setter for Oauth2 application secret.
     * 
     * @param oauth2AppSecret
     *            Oauth2 Application Secret
     */
    public void setAppSecret(String oauth2AppSecret) {
        log.trace("Entering & Leaving");
        this.appSecret = oauth2AppSecret;
    }

    /**
     * Getter for Oauth2 appication id.
     * 
     * @return Oauth2 application id
     */
    protected String getAppId() {
        log.trace("Entering & Leaving");
        return this.appId;
    }

    /**
     * Getter for Oauth2 application secret.
     * 
     * @return Oauth2 application secret
     */
    protected String getAppSecret() {
        log.trace("Entering & Leaving");
        return this.appSecret;
    }

    /**
     * Returns redirect url for authentication.
     * 
     * @param httpRequest
     *            the request
     * 
     * @return redirect url
     */
    public String getRedirectUrl(HttpServletRequest httpRequest) {
        log.trace("Entering");
        if (httpRequest == null) {
            log.trace("Leaving");
            return null;
        }
        OAuth2Parameters params = new OAuth2Parameters();
        if (scope != null) {
            params.setScope(scope);
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.reset();
            md.update(httpRequest.getSession().getId().getBytes());
            String digest = new String(Hex.encode(md.digest()));
            params.setState(digest);
        } catch (NoSuchAlgorithmException e) {
            log.error("Unable to generate state");
            e.printStackTrace();
            log.trace("Leaving");
            return null;
        }
        params.setRedirectUri(httpRequest.getRequestURL().toString());
        String authorizeUrl = oauthOperations.buildAuthorizeUrl(
                GrantType.AUTHORIZATION_CODE, params);
        log.trace("Leaving");
        return authorizeUrl;

    }

    /** 
     * Throws an error if state parameter is not the expected one.
     * 
     * @param httpRequest is the httpRequest we check for state.
     * @throws SocialUserAuthenticationException if the parameter is missing or mismatches.
     * */
    private void validateState(HttpServletRequest httpRequest)
            throws SocialUserAuthenticationException {
        log.trace("Entering");
        String state = httpRequest.getParameter("state");
        if (state == null) {
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(
                    "State parameter missing", SocialUserErrorIds.EXCEPTION);
        }
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            log.error("Unable to generate state");
            e.printStackTrace();
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(
                    "Unable to hash, use some other method",
                    SocialUserErrorIds.EXCEPTION);
        }
        md.reset();
        md.update(httpRequest.getSession().getId().getBytes());
        String cmpState = new String(Hex.encode(md.digest()));
        if (!state.equalsIgnoreCase(cmpState)) {
            log.error("state parameter mismatch");
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(
                    "State parameter mismatch", SocialUserErrorIds.EXCEPTION);
        }
    }

    /**
     * Throws an error if user authentication has failed Returns Authorization
     * Code if such exists Returns null if authentication has not been performed
     * yet.
     * 
     * @param httpRequest is the request
     * @return authorization code
     * @throws SocialUserAuthenticationException if there is no valid code.
     */
 // Checkstyle: CyclomaticComplexity OFF    
    private String getAuthorizationCode(HttpServletRequest httpRequest)
            throws SocialUserAuthenticationException {
        log.trace("Entering");
        String error = httpRequest.getParameter("error");
        if (error != null && !error.isEmpty()) {
            log.trace("Leaving");
            String event = SocialUserErrorIds.EXCEPTION;
            switch (error) {
            case "invalid_request":
            case "unauthorized_client":
            case "access_denied":
            case "unsupported_response_type":
            case "invalid_scope":
            case "server_error":
            case "temporarily_unavailable":
                event = SocialUserErrorIds.EXCEPTION;
                break;
            default :
                event = SocialUserErrorIds.EXCEPTION;
                break;    
            }
            String errorDescription = httpRequest
                    .getParameter("error_description");
            if (errorDescription != null && !errorDescription.isEmpty()) {
                error += " : " + errorDescription;
            }
            log.debug("Authentication failed: " + error);
            throw new SocialUserAuthenticationException(error, event);
        }
        String authorizationCode = httpRequest.getParameter("code");
        log.trace("Leaving");
        return authorizationCode;
    }
 // Checkstyle: CyclomaticComplexity ON    

    /**
     * Returns Access Grant if user is known, otherwise null.
     * 
     * @param httpRequest
     *            the request
     * @return Access Grant
     * @throws SocialUserAuthenticationException if the operation fails.
     */
    public AccessGrant getAccessGrant(HttpServletRequest httpRequest)
            throws SocialUserAuthenticationException {
        log.trace("Entering");
        AccessGrant accessGrant = null;
        try {
            String authorizationCode = getAuthorizationCode(httpRequest);
            if (authorizationCode == null) {
                return null;
            }
            validateState(httpRequest);
            accessGrant = oauthOperations.exchangeForAccess(authorizationCode,
                    httpRequest.getRequestURL().toString(), null);
        } catch (HttpClientErrorException e) {
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(e.getMessage(),
                    SocialUserErrorIds.EXCEPTION);
        }
        log.trace("Leaving");
        return accessGrant;
    }

}
