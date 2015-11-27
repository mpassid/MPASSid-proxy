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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.idp.authn.SocialUserAuthenticationException;
import fi.okm.mpass.idp.authn.SocialRedirectAuthenticator;
import fi.okm.mpass.idp.authn.SocialUserErrorIds;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.Prompt.Type;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** Class for implementing OpenId Connect authentication. */
public class OpenIdConnectIdentity extends AbstractOAuth2Identity implements
        SocialRedirectAuthenticator {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(OpenIdConnectIdentity.class);

    /** OIDC Prompt. */
    private Prompt prompt;
    /** OIDC Authentication Class Reference values. */
    private List<ACR> acrs;
    /** OIDC Display. */
    private Display display;

   
    
    
    
    /**
     * Setter for OpenId Scope values.
     * 
     * @param oidcScopes
     *            OpenId Scope values
     */
    public void setScope(List<String> oidcScopes) {
        log.trace("Entering");
        for (String oidcScope : oidcScopes) {
            switch (oidcScope.toUpperCase()) {
            case "ADDRESS":
                getScope().add(OIDCScopeValue.ADDRESS);
                break;
            case "EMAIL":
                getScope().add(OIDCScopeValue.EMAIL);
                break;
            case "OFFLINE_ACCESS":
                getScope().add(OIDCScopeValue.OFFLINE_ACCESS);
                break;
            case "PHONE":
                getScope().add(OIDCScopeValue.PHONE);
                break;
            case "PROFILE":
                getScope().add(OIDCScopeValue.PROFILE);
                break;
            default:
            }
        }
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Prompt value.
     * 
     * @param oidcPrompt
     *            OpenId Prompt values
     */
    public void setPrompt(String oidcPrompt) {
        log.trace("Entering");
        this.prompt = new Prompt(oidcPrompt);
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId ACR values.
     * 
     * @param oidcAcrs
     *            OpenId ACR values
     */
    public void setAcr(List<String> oidcAcrs) {
        log.trace("Entering");
        for (String oidcAcr : oidcAcrs) {
            ACR acr = new ACR(oidcAcr);
            this.acrs.add(acr);
        }
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Display value.
     * 
     * @param oidcDisplay
     *            OpenId Display values
     */
    public void setDisplay(String oidcDisplay) {
        log.trace("Entering");
        try {
            this.display = Display.parse(oidcDisplay);
        } catch (ParseException e) {
            log.error("Something bad happened "+e.getMessage());
        }
        log.trace("Leaving");
    }

    @Override
    public void init() {
        getScope().add(OIDCScopeValue.OPENID);

    }

    /** 
     * Checks if the initialized prompt has to be changed
     * due to authentication request.
     * 
     * @param httpRequest the request containing auth req data
     * @return updated prompt
     */
    private Prompt getPromptForRedirectUrl(HttpServletRequest httpRequest) {
        log.trace("Entering");
        if (getAuthenticationRequest() == null) {
            log.trace("Leaving");
            // no need to modify, helper not available
            return prompt;
        }
        if (getAuthenticationRequest().isPassive(httpRequest)) {
            Prompt newPrompt = new Prompt();
            newPrompt.add(Type.NONE);
            log.trace("Leaving");
            return newPrompt;
        }
        log.trace("Leaving");
        return prompt;
    }

    @Override
    public String getRedirectUrl(HttpServletRequest httpRequest) {
        log.trace("Entering");
        if (httpRequest == null) {
            log.trace("Leaving");
            return null;
        }
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        httpRequest.getSession().setAttribute("fi.okm.mpass.state", state);
        try {
            if (getAuthenticationRequest() == null) {
                log.trace("Leaving");
                return new AuthenticationRequest.Builder(responseType,
                        getScope(), getClientId(), new URI(httpRequest
                                .getRequestURL().toString()))
                        .endpointURI(getAuthorizationEndpoint())
                        .display(display).acrValues(acrs).prompt(prompt)
                        .state(state).build().toURI().toString();
            }
            if (getAuthenticationRequest().isForcedAuth(httpRequest)) {
                log.trace("Leaving");
                return new AuthenticationRequest.Builder(responseType,
                        getScope(), getClientId(), new URI(httpRequest
                                .getRequestURL().toString()))
                        .endpointURI(getAuthorizationEndpoint())
                        .display(display)
                        .acrValues(acrs)
                        .prompt(getPromptForRedirectUrl(httpRequest))
                        .state(state)
                        .loginHint(
                                getAuthenticationRequest().getLoginHint(
                                        httpRequest)).maxAge(0).build().toURI()
                        .toString();
            }
            log.trace("Leaving");
            return new AuthenticationRequest.Builder(responseType, getScope(),
                    getClientId(), new URI(httpRequest.getRequestURL()
                            .toString()))
                    .endpointURI(getAuthorizationEndpoint())
                    .display(display)
                    .acrValues(acrs)
                    .prompt(getPromptForRedirectUrl(httpRequest))
                    .state(state)
                    .loginHint(
                            getAuthenticationRequest()
                                    .getLoginHint(httpRequest)).build().toURI()
                    .toString();

        } catch (URISyntaxException | SerializeException e) {
            log.error("Something bad happened "+e.getMessage());
            log.trace("Leaving");
            return null;
        }

    }

    @Override
    public Subject getSubject(HttpServletRequest httpRequest)
            throws SocialUserAuthenticationException {
        log.trace("Entering");
        if (httpRequest == null) {
            log.trace("Leaving");
            return null;
        }
        TokenRequest request = getTokenRequest(httpRequest);
        if (request == null) {
            log.debug("User is not authenticated yet");
            log.trace("Leaving");
            return null;
        }
        OIDCAccessTokenResponse oidcAccessTokenResponse = null;
        Subject subject = new Subject();
        try {
            // add mapped claims as principals
            oidcAccessTokenResponse = (OIDCAccessTokenResponse) OIDCTokenResponseParser
                    .parse(request.toHTTPRequest().send());
            if (!oidcAccessTokenResponse.indicatesSuccess()) {
                log.trace("Leaving");
                throw new SocialUserAuthenticationException(
                        "access token response error",
                        SocialUserErrorIds.EXCEPTION);
            }
            log.debug("claims from provider: "+oidcAccessTokenResponse.getIDToken().getJWTClaimsSet());
            parsePrincipalsFromClaims(subject, oidcAccessTokenResponse.getIDToken().getJWTClaimsSet().toJSONObject());
        } catch (SerializeException | IOException | java.text.ParseException
                | ParseException e) {
            log.error("Something bad happened "+e.getMessage());
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(e.getMessage(),
                    SocialUserErrorIds.EXCEPTION);
        }
        log.trace("Leaving");
        return subject;

    }
   

}
