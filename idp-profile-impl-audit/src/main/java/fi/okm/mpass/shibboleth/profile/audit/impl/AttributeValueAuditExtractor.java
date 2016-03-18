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
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

/** 
 * A {@link Function} that returns the value for the configured attribute ID from an 
 * {@link AttributeContext}.
 */
public class AttributeValueAuditExtractor implements Function<ProfileRequestContext,Collection<String>> {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AttributeValueAuditExtractor.class);

    /** Lookup strategy for AttributeContext to read from. */
    @Nonnull private final Function<ProfileRequestContext,AttributeContext> attributeContextLookupStrategy;

    /** The attribute id whose value will be returned by this {@link Function}. */
    @Nonnull @NotEmpty private final String attributeId;
    
    /**
     * Constructor.
     * 
     * @param attrId The attributeId whose value is returned by this {@link Function}.
     */
    public AttributeValueAuditExtractor(@Nonnull @NotEmpty final String attrId) {
        // Defaults to ProfileRequestContext -> RelyingPartyContext -> AttributeContext.
        this(Functions.compose(new ChildContextLookup<>(AttributeContext.class),
                new ChildContextLookup<ProfileRequestContext,RelyingPartyContext>(RelyingPartyContext.class)), attrId);
    }
    
    /**
     * Constructor.
     *
     * @param strategy lookup strategy for {@link AttributeContext}
     * @param attrId The attributeId whose value is returned by this {@link Function}.
     */
    public AttributeValueAuditExtractor(@Nonnull final Function<ProfileRequestContext,AttributeContext> strategy, 
            @Nonnull @NotEmpty final String attrId) {
        attributeContextLookupStrategy = Constraint.isNotNull(strategy,
                "AttributeContext lookup strategy cannot be null");
        attributeId = Constraint.isNotEmpty(attrId, "attrId cannot be null nor empty!");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public Collection<String> apply(@Nullable final ProfileRequestContext input) {
        final AttributeContext attributeCtx = attributeContextLookupStrategy.apply(input);
        if (attributeCtx != null && attributeCtx.getIdPAttributes().keySet().contains(attributeId)) {
            final List<IdPAttributeValue<?>> values = attributeCtx.getIdPAttributes().get(attributeId).getValues();
            final Collection<String> attributeValue = new ArrayList<String>();
            log.debug("Iterating through the set of {} attribute values", values.size());
            for (int i = 0; i < values.size(); i++) {
                log.debug("Adding {} to the result collection", values.get(i).getValue());
                attributeValue.add(values.get(i).getValue().toString());
            }
            return attributeValue;
        } else {
            log.warn("Could not find the attribute {} from AttributeContext", attributeId);
            return Collections.emptyList();
        }
    }

}