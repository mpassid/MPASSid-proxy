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

import java.util.Enumeration;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.shibboleth.authn.context.ShibbolethAuthnContext;

/**
 * An action that extracts a Http headers and request attributes, creates and populates a 
 * {@link ShibbolethAuthnContext}, and attaches it to the {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @post If getHttpServletRequest() != null, HTTP headers and request attributes with String values are
 * extracted to populate a {@link ShibbolethAuthnContext}. */
@SuppressWarnings("rawtypes")
public class ExtractShibbolethAttributesFromRequest extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractShibbolethAttributesFromRequest.class);
    
    /** The possible prefix for the Shibboleth attribute names. */
    private final String variablePrefix;

    /**
     * Constructor.
     */
    public ExtractShibbolethAttributesFromRequest() {
        this("");
    }
    
    /**
     * Constructor.
     * 
     * @param prefix The possible prefix for the Shibboleth header/attribute names.
     */
    public ExtractShibbolethAttributesFromRequest(String prefix) {
        super();
        variablePrefix = prefix;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        if (log.isTraceEnabled()) {
            logHeadersAndAttributes(request);
        }
        final ShibbolethAuthnContext shibbolethContext =
                authenticationContext.getSubcontext(ShibbolethAuthnContext.class, true);
        final Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            final String header = headerNames.nextElement();
            final String value = StringSupport.trimOrNull(request.getHeader(header));
            updateShibbolethContext(shibbolethContext, header, value, true);
        }
        final Enumeration<String> attributeNames = request.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            final String name = attributeNames.nextElement();
            if (request.getAttribute(name) instanceof String) {
                final String value = StringSupport.trimOrNull((String)request.getAttribute(name));
                updateShibbolethContext(shibbolethContext, name, value, false);
            } else {
                log.debug("{} Ignoring request attribute {}", getLogPrefix(), name);
            }
        }
    }
    
    /**
     * Updates the given {@link ShibbolethContext} with given parameters.
     * @param shibbolethContext The Shibboleth context.
     * @param name The name of the variable to be updated.
     * @param value The value of the variable to be updated.
     * @param isHeader Is the variable HTTP header (if false, it's request attribute).
     */
    protected void updateShibbolethContext(final ShibbolethAuthnContext shibbolethContext, 
            final String name, final String value, final boolean isHeader) {
        if (value == null) {
            log.trace("{} The value is null, {} will be ignored", getLogPrefix(), name);
            return;
        }
        final String key = stripPrefixIfExists(name);
        if (key.equals(ShibbolethAuthnContext.SHIB_SP_IDENTITY_PROVIDER)) {
            log.debug("{} Added value for Identity Provider", getLogPrefix());
            shibbolethContext.setIdp(applyTransforms(value));            
        } else if (key.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_AUTHENTICATION_INSTANT)) {
            log.debug("{} Added value for Authentication Instant", getLogPrefix());
            shibbolethContext.setInstant(applyTransforms(value));
        } else if (key.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_AUTHENTICATION_METHOD)) {
            log.debug("{} Added value for Authentication Method", getLogPrefix());
            shibbolethContext.setMethod(applyTransforms(value));
        } else if (key.equals(variablePrefix + ShibbolethAuthnContext.SHIB_SP_AUTHN_CONTEXT_CLASS)) {
            log.debug("{} Added value for Authentication Context Class", getLogPrefix());
            shibbolethContext.setContextClass(applyTransforms(value));
        } else {       
            if (isHeader) {
                log.debug("{} Added value for header {}", getLogPrefix(), key);
                shibbolethContext.getHeaders().put(key, applyTransforms(value));
            } else {
                log.debug("{} Added value for attribute {}", getLogPrefix(), key);
                shibbolethContext.getAttributes().put(key, applyTransforms(value));
            }
        }
    }
    
    /**
     * Strips the variablePrefix from the given String if exists.
     * @param name The String to be checked.
     * @return name without variablePrefix, if it existed.
     */
    protected String stripPrefixIfExists(@Nonnull final String name) {
        if (name.startsWith(variablePrefix)) {
            return name.substring(variablePrefix.length());
        }
        return name;
    }

    /**
     * Iterates over HTTP headers and attributes and logs their value in TRACE-level.
     * @param request The servlet request.
     */
    protected void logHeadersAndAttributes(HttpServletRequest request) {
        final Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            final String header = headerNames.nextElement();
            final String value = request.getHeader(header);
            log.trace("Header name {} has value {}", header, value);
        }
        final Enumeration<String> attributeNames = request.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            final String attribute = attributeNames.nextElement();
            log.trace("Attribute name {} has value {}", attribute, request.getAttribute(attribute));
        }
    }
}
