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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** Class for implementing OpenId Connect authentication. */
public class OpenIdConnectIdentity implements SocialRedirectAuthenticator {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(OpenIdConnectIdentity.class);

    /** OIDC Scope. */
    private Scope scope;
    /** OIDC Prompt. */
    private Prompt prompt;
    /** OIDC Authentication Class Reference values. */
    private List<ACR> acrs;
    /** OIDC Display. */
    private Display display;
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
     * Setter for OpenId Scope values.
     * 
     * @param oidcScopes
     *            OpenId Scope values
     */
    public void setScope(List<String> oidcScopes) {
        log.trace("Entering");
        if (scope == null) {
            scope = new Scope();
        }
        for (String oidcScope : oidcScopes) {
            switch (oidcScope.toUpperCase()) {
            case "ADDRESS":
                scope.add(OIDCScopeValue.ADDRESS);
                break;
            case "EMAIL":
                scope.add(OIDCScopeValue.EMAIL);
                break;
            case "OFFLINE_ACCESS":
                scope.add(OIDCScopeValue.OFFLINE_ACCESS);
                break;
            case "PHONE":
                scope.add(OIDCScopeValue.PHONE);
                break;
            case "PROFILE":
                scope.add(OIDCScopeValue.PROFILE);
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

    /**
     * Sets map of claims to principals.
     * 
     * @param oidcClaimsPrincipals
     *            map of supported implementations
     * */
    public void setClaimsPrincipals(Map<String, String> oidcClaimsPrincipals) {
        log.trace("Entering");
        this.claimsPrincipals = oidcClaimsPrincipals;
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId authorization endpoint.
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
     * Setter for OpenId revocation endpoint.
     * 
     * @param endPoint
     *            OpenId RevocationEndpoint
     * @throws URISyntaxException
     */
    public void setrevocationEndpoint(String endPoint)
            throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.revocationEndpoint = new URI(endPoint);
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
     * Setter for Oauth2 Client secret.
     * 
     * @param oauth2ClientSecret
     *            Oauth2 Client Secret
     */
    public void setClientSecret(String oauth2ClientSecret) {
        log.trace("Entering & Leaving");
        this.clientSecret = new Secret(oauth2ClientSecret);
    }

    @Override
    public void init() {
        if (scope == null) {
            scope = new Scope();
        }
        scope.add(OIDCScopeValue.OPENID);

    }

    @Override
    public String getRedirectUrl(HttpServletRequest httpRequest)  {
        log.trace("Entering");
        ResponseType responseType = new ResponseType(
                ResponseType.Value.CODE);
        State state = new State();
        httpRequest.getSession().setAttribute("fi.okm.mpass.state", state);
        String ret=null;
        try {
            AuthenticationRequest request = new AuthenticationRequest.Builder(
                    responseType, scope, clientID, new URI(httpRequest
                            .getRequestURL().toString()))
                    .endpointURI(authorizationEndpoint).display(display)
                    .acrValues(acrs).prompt(prompt).state(state).build();
            ret=request.toURI().toString();
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
        AuthenticationResponse response = null;
        try {
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
            // TODO: check state
            AuthorizationCode code = successResponse.getAuthorizationCode();
            URI callback = new URI(httpRequest.getRequestURL().toString());
            AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code,
                    callback);
            ClientAuthentication clientAuth = new ClientSecretBasic(clientID,
                    clientSecret);
            TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth,
                    codeGrant);
            OIDCAccessTokenResponse oidcAccessTokenResponse = null;
            
            State state = (State) httpRequest.getSession().getAttribute(
                    "fi.okm.mpass.state");
            if (state==null || !state.equals(successResponse.getState())){
                throw new SocialRedirectAuthenticationException(
                        "State parameter not satisfied", AuthnEventIds.AUTHN_EXCEPTION);
            }
            
            Subject subject = new Subject();
            try {
                // add mapped claims as principals
                oidcAccessTokenResponse = (OIDCAccessTokenResponse) OIDCTokenResponseParser
                        .parse(request.toHTTPRequest().send());
                boolean first = true;
                for (Map.Entry<String, String> entry : claimsPrincipals
                        .entrySet()) {
                    subject.getPrincipals().add(
                            new SocialUserPrincipal(Types.valueOf(entry
                                    .getValue()), oidcAccessTokenResponse
                                    .getIDToken().getJWTClaimsSet()
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
            } catch (SerializeException | IOException
                    | java.text.ParseException | ParseException e) {
                e.printStackTrace();
                log.trace("Leaving");
                throw new SocialRedirectAuthenticationException(e.getMessage(),
                        AuthnEventIds.AUTHN_EXCEPTION);
            }
            log.trace("Leaving");
            return subject;
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
