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
import java.util.Map;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.idp.authn.SocialRedirectAuthenticationException;
import fi.okm.mpass.idp.authn.SocialRedirectAuthenticator;
import fi.okm.mpass.idp.authn.principal.SocialUserPrincipal;
import fi.okm.mpass.idp.authn.principal.SocialUserPrincipal.Types;

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
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        log.trace("Leaving");
    }

    @Override
    public void init() {
        getScope().add(OIDCScopeValue.OPENID);

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
        String ret = null;
        try {
            AuthenticationRequest request = new AuthenticationRequest.Builder(
                    responseType, getScope(), getClientId(), new URI(
                            httpRequest.getRequestURL().toString()))
                    .endpointURI(getAuthorizationEndpoint()).display(display)
                    .acrValues(acrs).prompt(prompt).state(state).build();
            ret = request.toURI().toString();
        } catch (URISyntaxException | SerializeException e) {
            e.printStackTrace();
            log.trace("Leaving");
            return null;
        }
        log.trace("Leaving");
        return ret;

    }

    @Override
    public Subject getSubject(HttpServletRequest httpRequest)
            throws SocialRedirectAuthenticationException {
        log.trace("Entering");
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
                throw new SocialRedirectAuthenticationException(
                        "access token response error",
                        AuthnEventIds.AUTHN_EXCEPTION);
            }
            boolean first = true;
            for (Map.Entry<String, String> entry : getClaimsPrincipals()
                    .entrySet()) {
                subject.getPrincipals().add(
                        new SocialUserPrincipal(
                                Types.valueOf(entry.getValue()),
                                oidcAccessTokenResponse.getIDToken()
                                        .getJWTClaimsSet()
                                        .getClaim(entry.getKey()).toString()));
                // first mapped claim is also username principal
                if (first) {
                    subject.getPrincipals().add(
                            new UsernamePrincipal(oidcAccessTokenResponse
                                    .getIDToken().getJWTClaimsSet()
                                    .getClaim(entry.getKey()).toString()));
                    first = false;
                }
            }
        } catch (SerializeException | IOException | java.text.ParseException
                | ParseException e) {
            e.printStackTrace();
            log.trace("Leaving");
            throw new SocialRedirectAuthenticationException(e.getMessage(),
                    AuthnEventIds.AUTHN_EXCEPTION);
        }
        log.trace("Leaving");
        return subject;

    }

}
