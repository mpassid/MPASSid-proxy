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

import java.text.ParseException;
import java.util.Date;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.idp.authn.SocialUserAuthenticationException;
import fi.okm.mpass.idp.authn.SocialUserErrorIds;

/**
 * An action that verifies Authentication Time of ID Token.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 */
@SuppressWarnings("rawtypes")
public class ValidateOIDCIDTokenAuthenticationTime extends
        AbstractAuthenticationAction {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE
     * IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(ValidateOIDCIDTokenAuthenticationTime.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(
            @Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        if (!authenticationContext.isForceAuthn()) {
            log.trace("Leaving");
            return;
        }
        // If we have forced authentication, we will check for authentication
        // age
        // It must not be more than now-30s.
        final SocialUserOpenIdConnectContext suCtx = authenticationContext
                .getSubcontext(SocialUserOpenIdConnectContext.class, true);
        if (suCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        Date authTime;
        try {
            authTime = suCtx.getOidcTokenResponse().getOIDCTokens()
                    .getIDToken().getJWTClaimsSet().getDateClaim("auth_time");
        } catch (ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (authTime == null) {
            log.error("{} max age set but no auth_time received",
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");

        }
        // TODO: 30000, make it as leeway init param
        // Authentication must have been done within 30secs
        Date currentDate = new Date();
        if (currentDate.getTime() - authTime.getTime() > 30000) {
            log.error("current time " + currentDate.getTime());
            log.error("authentication time " + currentDate.getTime());
        }
        log.trace("Leaving");
        return;
    }

}
