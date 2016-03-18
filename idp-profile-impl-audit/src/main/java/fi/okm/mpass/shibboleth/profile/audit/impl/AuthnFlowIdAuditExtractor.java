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
package fi.okm.mpass.shibboleth.profile.audit.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

/**
 * A {@link Function} that returns the value of authentication flow id from the {@link AuthenticationResult}
 * in the {@link AuthenticationContext}.
 */
@SuppressWarnings("rawtypes")
public class AuthnFlowIdAuditExtractor implements Function<ProfileRequestContext,Collection<String>> {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AuthnFlowIdAuditExtractor.class);

    /** Lookup strategy for AttributeContext to read from. */
    @Nonnull private final Function<ProfileRequestContext, AuthenticationContext> authenticationContextLookupStrategy;

    /** Constructor. */
    @SuppressWarnings("unchecked")
    public AuthnFlowIdAuditExtractor() {
        this((Function)new ChildContextLookup<>(AuthenticationContext.class));
    }
    
    /**
     * Constructor.
     *
     * @param strategy lookup strategy for {@link AuthenticationContext}
     */
    public AuthnFlowIdAuditExtractor(@Nonnull final Function<ProfileRequestContext,AuthenticationContext> strategy) {
        authenticationContextLookupStrategy = Constraint.isNotNull(strategy,
                "AuthenticationContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public Collection<String> apply(@Nullable final ProfileRequestContext input) {
        final AuthenticationContext authenticationCtx = authenticationContextLookupStrategy.apply(input);
        if (authenticationCtx != null && authenticationCtx.getAuthenticationResult() != null) {
            log.debug("Authentication context found, returning {}", 
                    authenticationCtx.getAuthenticationResult().getAuthenticationFlowId());
            final Collection<String> attributeValue = new ArrayList<String>();
            attributeValue.add(authenticationCtx.getAuthenticationResult().getAuthenticationFlowId());
            return attributeValue;
        } else {
            log.warn("Could not find the AuthenticationResult");
            return Collections.emptyList();
        }
    }
}
