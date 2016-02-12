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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.idp.authn.SocialUserAuthenticationException;
import fi.okm.mpass.idp.authn.SocialRedirectAuthenticator;
import fi.okm.mpass.idp.authn.SocialUserErrorIds;

import com.nimbusds.jwt.JWT;
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

    /** OP Issuer identifier. */
    private String issuer;
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
     * Setter for OpenId Provider Issuer identifier value.
     * 
     * @param oidcIssuer
     *            OpenId Provider Issuer identifier
     */
    public void setIssuer(String oidcIssuer) {
        log.trace("Entering");
        this.issuer = oidcIssuer;
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
            if (this.acrs == null) {
                this.acrs = new ArrayList<ACR>();
            }
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
            log.error("Something bad happened " + e.getMessage());
        }
        log.trace("Leaving");
    }

    @Override
    public void init() {
        getScope().add(OIDCScopeValue.OPENID);

    }

    /**
     * Checks if the initialized prompt has to be changed due to authentication
     * request.
     * 
     * @param httpRequest
     *            the request containing auth req data
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

    /**
     * Checks if the idtoken passes validity checks.
     * 
     * @param iDToken
     *            to be verified
     * @param httpRequest
     *            to check attribute values
     * @throws SocialUserAuthenticationException
     *             if validity check is not passed
     */
    // Checkstyle: CyclomaticComplexity OFF
    private void verifyIDToken(JWT iDToken, HttpServletRequest httpRequest)
            throws SocialUserAuthenticationException {
        log.trace("Entering");
        if (iDToken == null) {
            throw new SocialUserAuthenticationException("IDToken is null",
                    SocialUserErrorIds.EXCEPTION);
        }
        if (httpRequest == null) {
            throw new SocialUserAuthenticationException("HttpRequest is null",
                    SocialUserErrorIds.EXCEPTION);
        }
        try {

            // The Issuer Identifier for the OpenID Provider (which is typically
            // obtained during Discovery) MUST exactly match the value of the
            // iss (issuer) Claim.
            if (issuer == null) {
                log.warn("Issuer not set, cannot be verified");
            } else {
                if (!issuer.equals(iDToken.getJWTClaimsSet().getIssuer())) {
                    log.error("issuer mismatch");
                    throw new SocialUserAuthenticationException(
                            "issuer mismatch", SocialUserErrorIds.EXCEPTION);

                }
            }

            // The Client MUST validate that the aud (audience) Claim contains
            // its client_id value registered at the Issuer identified by the
            // iss (issuer) Claim as an audience. The aud (audience) Claim MAY
            // contain an array with more than one element. The ID Token MUST be
            // rejected if the ID Token does not list the Client as a valid
            // audience, or if it contains additional audiences not trusted by
            // the Client.
            if (!iDToken.getJWTClaimsSet().getAudience()
                    .contains(getClientId().getValue())) {
                throw new SocialUserAuthenticationException(
                        "client is not the intended audience",
                        SocialUserErrorIds.EXCEPTION);
            }
            // If the ID Token contains multiple audiences, the Client SHOULD
            // verify that an azp Claim is present.
            // If an azp (authorized party) Claim is present, the Client SHOULD
            // verify that its client_id is the Claim Value.
            if (iDToken.getJWTClaimsSet().getAudience().size() > 1) {
                String azp = iDToken.getJWTClaimsSet().getStringClaim("azp");
                if (!getClientId().getValue().equals(azp)) {
                    throw new SocialUserAuthenticationException(
                            "multiple audiences, client is not the azp",
                            SocialUserErrorIds.EXCEPTION);
                }
            }

            // No signature check
            // If the ID Token is received via direct communication between the
            // Client and the Token Endpoint (which it is in this flow), the TLS
            // server validation MAY be used to validate the issuer in place of
            // checking the token signature. The Client MUST validate the
            // signature of all other ID Tokens according to JWS [JWS] using the
            // algorithm specified in the JWT alg Header Parameter. The Client
            // MUST use the keys provided by the Issuer.

            // Check time
            // The current time MUST be before the time represented by the exp
            // Claim.
            Date currentDate = new Date();
            // if exp is not present throws nullpointer Exception
            // we give no leeway.
            if (currentDate
                    .after(iDToken.getJWTClaimsSet().getExpirationTime())) {
                log.error("current date " + currentDate);
                log.error("exp "
                        + iDToken.getJWTClaimsSet().getExpirationTime());
                throw new SocialUserAuthenticationException("exp expired",
                        SocialUserErrorIds.EXCEPTION);
            }

            // NOT USING NONCE & IAT (yet?)
            // The iat Claim can be used to reject tokens that were issued too
            // far away from the current time, limiting the amount of time that
            // nonces need to be stored to prevent attacks. The acceptable range
            // is Client specific.

            // If a nonce value was sent in the Authentication Request, a nonce
            // Claim MUST be present and its value checked to verify that it is
            // the same value as the one that was sent in the Authentication
            // Request. The Client SHOULD check the nonce value for replay
            // attacks. The precise method for detecting replay attacks is
            // Client specific.

            // Check acr
            // If the acr Claim was requested, the Client SHOULD check that the
            // asserted Claim Value is appropriate. The meaning and processing
            // of acr Claim Values is out of scope for this specification.
            if (acrs != null && acrs.size() > 0) {
                String acr = iDToken.getJWTClaimsSet().getStringClaim("acr");
                if (acr == null) {
                    log.error("acr requested but not received");
                    throw new SocialUserAuthenticationException(
                            "acr requested but not received",
                            SocialUserErrorIds.EXCEPTION);
                }
                if (!acrs.contains(acr)) {
                    log.error("acr received does not match requested:" + acr);
                    throw new SocialUserAuthenticationException(
                            "acr requested does not match the received value",
                            SocialUserErrorIds.EXCEPTION);
                }

            }

            // Check auth time
            // If the auth_time Claim was requested, either through a specific
            // request for this Claim or by using the max_age parameter, the
            // Client SHOULD check the auth_time Claim value and request
            // re-authentication if it determines too much time has elapsed
            // since the last End-User authentication.
            if ((boolean) httpRequest.getSession().getAttribute(
                    "fi.okm.mpass.forced")) {
                log.debug("forced is on");
                // for forced authentication we have set max_age = 0
                Date authTime = iDToken.getJWTClaimsSet().getDateClaim(
                        "auth_time");
                if (authTime == null) {
                    log.error("max age set but no auth_time received");
                    throw new SocialUserAuthenticationException(
                            "max age set but no auth_time received",
                            SocialUserErrorIds.EXCEPTION);

                }
                // TODO: 30000, make it as leeway init param
                if (currentDate.getTime() - authTime.getTime() > 30000) {
                    log.error("current time " + currentDate.getTime());
                    log.error("authentication time " + currentDate.getTime());
                    throw new SocialUserAuthenticationException(
                            "auth_time not acceptable",
                            SocialUserErrorIds.EXCEPTION);
                }

            }

        } catch (java.text.ParseException e) {
            throw new SocialUserAuthenticationException(
                    "problem parsing token", SocialUserErrorIds.EXCEPTION);
        }
        log.trace("Leaving");
    }

    // Checkstyle: CyclomaticComplexity ON

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
        // we set attribute to store the forced value
        httpRequest.getSession().setAttribute("fi.okm.mpass.forced", false);
        String ret = null;
        try {
            if (getAuthenticationRequest() == null) {
                ret = new AuthenticationRequest.Builder(responseType,
                        getScope(), getClientId(), new URI(httpRequest
                                .getRequestURL().toString()))
                        .endpointURI(getAuthorizationEndpoint())
                        .display(display).acrValues(acrs).prompt(prompt)
                        .state(state).build().toURI().toString();
                log.debug("Constructed redirect string " + ret);
                return ret;
            }
            if (getAuthenticationRequest().isForcedAuth(httpRequest)) {
                httpRequest.getSession().setAttribute("fi.okm.mpass.forced",
                        true);
                ret = new AuthenticationRequest.Builder(responseType,
                        getScope(), getClientId(), new URI(httpRequest
                                .getRequestURL().toString()))
                        .endpointURI(getAuthorizationEndpoint())
                        .display(display)
                        .acrValues(acrs)
                        .prompt(getPromptForRedirectUrl(httpRequest))
                        .state(state)
                        .maxAge(0)
                        .loginHint(
                                getAuthenticationRequest().getLoginHint(
                                        httpRequest)).build().toURI()
                        .toString();
                log.debug("Constructed redirect string " + ret);
                return ret;
            }
            ret = new AuthenticationRequest.Builder(responseType, getScope(),
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
            log.debug("Constructed redirect string " + ret);
            return ret;

        } catch (URISyntaxException | SerializeException e) {
            log.error("Something bad happened " + e.getMessage());
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
            log.debug("claims from provider: "
                    + oidcAccessTokenResponse.getIDToken().getJWTClaimsSet());
            verifyIDToken(oidcAccessTokenResponse.getIDToken(), httpRequest);
            parsePrincipalsFromClaims(subject, oidcAccessTokenResponse
                    .getIDToken().getJWTClaimsSet().toJSONObject());
        } catch (SerializeException | IOException | java.text.ParseException
                | ParseException e) {
            log.error("Something bad happened " + e.getMessage());
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(e.getMessage(),
                    SocialUserErrorIds.EXCEPTION);
        }
        log.trace("Leaving");
        return subject;

    }

}
