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

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * An action that creates a {@link SocialUserOpenIdConnectContext}, and attaches
 * it to the {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class SetOIDCInformation extends AbstractExtractionAction {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE
     * IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(SetOIDCInformation.class);

    // TODO: replace with better suited class
    /** oidc methods and parameters. */
    private OpenIdConnectIdentity oidc;

    /**
     * Method for setting the openid connect parameters.
     * 
     * @param openIdConnectIdentity
     *            instance.
     */

    public void setOpenIdConnectInformation(
            @Nonnull OpenIdConnectIdentity openIdConnectIdentity) {
        log.trace("Entering");
        this.oidc = openIdConnectIdentity;
        log.trace("Leaving");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(
            @Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        if (oidc == null) {
            // TODO: FIX ERROR VALUE
            log.info("{} oidc parameters not set", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }

        final SocialUserOpenIdConnectContext suCtx = authenticationContext
                .getSubcontext(SocialUserOpenIdConnectContext.class, true);
        if (suCtx == null) {
            // TODO: FIX ERROR VALUE
            log.info("{} Not able to set oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }
        oidc.init();
        suCtx.setOpenIdConnectInformation(oidc);
        // form redirect url, set it to context
        // TODO: THIS IS STILL VERY DRAFT VERSION NOT SUPPORTING
        // AUTH REQUEST PARAMETERS ETC.
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        try {
            suCtx.setAuthenticationRequestURI(new AuthenticationRequest.Builder(
                    responseType,
                    oidc.getScope(),
                    oidc.getClientId(),
                    new URI(
                            "https://lauros.fi:8444/idp/Authn/SocialUserOpenIdConnectEnd"))
                    .endpointURI(oidc.getAuthorizationEndpoint())
                    .display(oidc.getDisplay()).acrValues(oidc.getAcr())
                    .prompt(oidc.getPrompt()).state(state).build().toURI());
        } catch (URISyntaxException e) {
            // TODO: FIX ERROR VALUE
            log.info("{} Not able to set oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.INVALID_AUTHN_CTX);
            log.trace("Leaving");
            return;
        }

        log.trace("Leaving");
        return;
    }

}
