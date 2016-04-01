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

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

/**
 * An action that creates a {@link SocialUserOpenIdConnectContext}, and attaches
 * it to the {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class GetOIDCTokenResponse extends AbstractExtractionAction {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE
     * IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(GetOIDCTokenResponse.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(
            @Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final SocialUserOpenIdConnectContext suCtx = authenticationContext
                .getSubcontext(SocialUserOpenIdConnectContext.class, true);
        if (suCtx == null) {
            // TODO: FIX ERROR VALUE
            log.info("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }

        AuthenticationSuccessResponse response = suCtx
                .getAuthenticationSuccessResponse();
        if (response == null) {
            // TODO: FIX ERROR VALUE
            log.info("{} No oidc authentication success response",
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }

        AuthorizationCode code = response.getAuthorizationCode();
        URI callback = null;
        try {
            // TODO: fix with proper paramter
            callback = new URI(
                    "https://lauros.fi:8444/idp/Authn/SocialUserOpenIdConnectEnd");
        } catch (URISyntaxException e) {
            // TODO: FIX ERROR VALUE
            log.info("{} invalid uri", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }

        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code,
                callback);
        ClientAuthentication clientAuth = new ClientSecretBasic(suCtx
                .getOpenIdConnectInformation().getClientId(), suCtx
                .getOpenIdConnectInformation().getClientSecret());
        TokenRequest tokenRequest;
        try {
            tokenRequest = new TokenRequest(suCtx.getOpenIdConnectInformation()
                    .getTokenEndpoint(), clientAuth, codeGrant);
        } catch (URISyntaxException e) {
            // TODO: FIX ERROR VALUE
            log.info("{} invalid uri", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }
        OIDCTokenResponse oidcTokenResponse = null;
        try {
            oidcTokenResponse = (OIDCTokenResponse) OIDCTokenResponseParser
                    .parse(tokenRequest.toHTTPRequest().send());
            if (!oidcTokenResponse.indicatesSuccess()) {
                // TODO: FIX ERROR VALUE
                log.info("{} token response does not indicate success",
                        getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext,
                        AuthnEventIds.INVALID_AUTHN_CTX);
                log.trace("Leaving");
                return;
            }

        } catch (SerializeException | IOException | ParseException e) {
            // TODO: FIX ERROR VALUE
            log.info("{} token response failed", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        log.debug("Storing oidc token response to context:"
                + oidcTokenResponse.toJSONObject().toJSONString());
        log.trace("Leaving");
        return;
    }

}
