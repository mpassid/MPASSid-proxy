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

package fi.okm.mpass.shibboleth.authn.impl;

import java.util.Iterator;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.shibboleth.authn.context.ShibbolethAuthnContext;
import fi.okm.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;

/**
 * This action parses the {@link ShibHeaderPrincipal}s from the subject and stores them inside the
 * {@link ShibbolethAuthnContext}.
 */
@SuppressWarnings("rawtypes")
public class ExtractShibPrincipalsFromSubject extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractShibPrincipalsFromSubject.class);

    /** The possible prefix for the Shibboleth attribute names. */
    private final String variablePrefix;

    /**
     * Constructor.
     * 
     * @param prefix The possible prefix for the Shibboleth attribute names.
     */
    public ExtractShibPrincipalsFromSubject(String prefix) {
        super();
        variablePrefix = prefix;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final AuthenticationResult authnResult = authenticationContext.getAuthenticationResult();
        authenticationContext.setResultCacheable(false);
        if (authnResult == null) {
            log.debug("{} Profile action does not contain an AuthenticationResult", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        final Subject subject = authnResult.getSubject();
        if (subject == null) {
            log.debug("{} Profile action does not contain a Subject", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        final Set<ShibHeaderPrincipal> principals = subject.getPrincipals(ShibHeaderPrincipal.class);
        if (principals == null || principals.isEmpty()) {
            log.debug("{} Profile action does not contain supported Principals, nothing else to do.", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_SUBJECT);
            return;
        }
        final ShibbolethAuthnContext shibbolethContext =
                authenticationContext.getSubcontext(ShibbolethAuthnContext.class, true);
        iteratePrincipals(principals, shibbolethContext);
    }
    
    /**
     * Iterate the set of {@link Principal}s and populate {@link ShibbolethAuthnContext}.
     * @param principals The set to be iterated over.
     * @param shibbolethContext The context to be populated.
     */
    protected void iteratePrincipals(final Set<ShibHeaderPrincipal> principals, 
            final ShibbolethAuthnContext shibbolethContext) {
        final Iterator<ShibHeaderPrincipal> iterator = principals.iterator();
        while (iterator.hasNext()) {
            final ShibHeaderPrincipal principal = iterator.next();
            final String name = principal.getKey();
            if (name.equals(ShibbolethAuthnContext.SHIB_SP_IDENTITY_PROVIDER)
                    || name.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_IDENTITY_PROVIDER)) {
                log.debug("{} Added value for Identity Provider", getLogPrefix());
                shibbolethContext.setIdp(applyTransforms(principal.getValue()));
            } else if (name.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_AUTHENTICATION_INSTANT)) {
                log.debug("{} Added value for Authentication Instant", getLogPrefix());
                shibbolethContext.setInstant(applyTransforms(principal.getValue()));
            } else if (name.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_AUTHENTICATION_METHOD)) {
                log.debug("{} Added value for Authentication Method", getLogPrefix());
                shibbolethContext.setMethod(applyTransforms(principal.getValue()));
            } else if (name.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_AUTHN_CONTEXT_CLASS)) {
                log.debug("{} Added value for Authentication Context Class", getLogPrefix());
                shibbolethContext.setContextClass(applyTransforms(principal.getValue()));
            } else {
                log.trace("{} Ignoring principal {}", getLogPrefix(), name);
            }
        }        
    }
}
