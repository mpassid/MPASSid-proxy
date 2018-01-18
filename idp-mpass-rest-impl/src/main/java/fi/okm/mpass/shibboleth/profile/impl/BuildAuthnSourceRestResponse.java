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

package fi.okm.mpass.shibboleth.profile.impl;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.opensaml.profile.action.EventIds;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import com.google.gson.Gson;

import fi.okm.mpass.shibboleth.rest.data.AuthnSourceDTO;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This action builds an {@link AuthnSourceDTO} and wraps it as JSON to the {@link HttpServletResponse}'s
 * output.
 */
public class BuildAuthnSourceRestResponse extends AbstractRestResponseAction {
    
    /** The default prefix for the principals populated to the tags. */
    public static final String DEFAULT_PRINCIPAL_PREFIX = "urn:mpass.id";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BuildAuthnSourceRestResponse.class);

    /** All the configured authentication flows to filter from. */
    private List<AuthenticationFlowDescriptor> flows;
    
    /** The list of ids of the active flows. */
    private List<String> activeFlowIds;
    
    /** The list of ids of the flows to be ignored. */
    private List<String> ignoredFlowIds;
    
    /** The complementary information for the authentication flows. */
    private Properties additionalInfo;
    
    /** The full flow information to be responded by the API. */
    private List<AuthnSourceDTO> flowInformation;

    /**
     * Set all the configured authentication flows to filter from.
     * @param allFlows What to set.
     */
    public void setFlows(final List<AuthenticationFlowDescriptor> allFlows) {
        flows = Constraint.isNotNull(allFlows, "The list of flows cannot be null!");
    }
    
    /**
     * Set the list of ids of the active flows.
     * @param flowIds What to set (<pre>|</pre> -separated list of flow ids)
     */
    public void setActiveFlowIds(final String flowIds) {
        activeFlowIds = new ArrayList<String>();
        log.trace("{} Processing {}", getLogPrefix(), flowIds);
        if (flowIds != null) {
            final StringTokenizer tokenizer = new StringTokenizer(flowIds, "|");
            while (tokenizer.hasMoreTokens()) {
                final String flowId = tokenizer.nextToken();
                log.debug("{} Set flow {} as active", getLogPrefix(), flowId);
                activeFlowIds.add(flowId);
            }
        } else {
            log.warn("{} No authentication flows configured to be active", getLogPrefix());
        }
    }
    
    /**
     * Set the complementary information for the authentication flows.
     * @param properties What to set.
     */
    public void setAdditionalInfo(final Properties properties) {
        additionalInfo = Constraint.isNotNull(properties, "The additional info properties cannot be null!");
    }
    
    /**
     * Set the list of ids of the flows to be ignored.
     * @param flowIds What to set.
     */
    public void setIgnoredFlowIds(final List<String> flowIds) {
        ignoredFlowIds = flowIds;
    }
    
    /**
     * Checks if the given flow exists in the list of ignored flows.
     * @param flow The flow to be checked.
     * @param flowId The (stripped) flow id to be checked.
     * @return true if it exists, false otherwise.
     */
    protected boolean isIgnoredFlow(final AuthenticationFlowDescriptor flow, final String flowId) {
        final Collection<Principal> principals = flow.getSupportedPrincipals();
        if (principals == null || principals.isEmpty()) {
            log.trace("{} Empty set of supported principals for {}, will be ignored", getLogPrefix(), flowId);
            return true;
        }
        boolean mpassPrincipalFound = false;
        for (final Principal principal : principals) {
            if (principal.getName().startsWith(DEFAULT_PRINCIPAL_PREFIX)) mpassPrincipalFound = true;
        }
        if (!mpassPrincipalFound) {
            return true;
        }
        if (ignoredFlowIds == null || ignoredFlowIds.isEmpty()) {
            return false;
        }
        return ignoredFlowIds.contains(flowId);
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        log.debug("Initializing");
        super.doInitialize();
        flowInformation = new ArrayList<AuthnSourceDTO>();
        for (final AuthenticationFlowDescriptor flow : flows) {
            final String id = (flow.getId().startsWith("authn")) ? flow.getId().substring(6) : flow.getId();
            if (activeFlowIds.contains(id) && !isIgnoredFlow(flow, id)) {
                log.debug("{} Adding flow {}", getLogPrefix(), id);
                final AuthnSourceDTO source = new AuthnSourceDTO();
                source.setId(id);
                source.setSupportsForced(flow.isForcedAuthenticationSupported());
                source.setSupportsPassive(flow.isPassiveAuthenticationSupported());
                source.setTitle(additionalInfo.getProperty(id + ".title"));
                source.setIconUrl(additionalInfo.getProperty(id + ".iconUrl"));
                source.setTags(getTags(flow, id));
                flowInformation.add(source);
            } else {
                log.trace("{} Ignoring {}", getLogPrefix(), id);
            }
        }
    }
    
    protected List<String> getTags(final AuthenticationFlowDescriptor flow, final String id) {
        final List<String> tags = new ArrayList<>();
        for (final Principal principal : flow.getSupportedPrincipals()) {
            final String name = principal.getName();
            if (name.startsWith(DEFAULT_PRINCIPAL_PREFIX) && !name.endsWith(id)) {
                tags.add(name);
                log.debug("{} Added {} as a tag for {}", getLogPrefix(), name, id);
            } else {
                log.trace("{} Ignoring {} from the list of tags", getLogPrefix(), name);
            }
        }
        return tags;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull public Event execute(@Nonnull final RequestContext springRequestContext) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);        
        final HttpServletRequest httpRequest = getHttpServletRequest();
        pushHttpResponseProperties();
        final HttpServletResponse httpResponse = getHttpServletResponse();

        try {
            final Writer out = new OutputStreamWriter(httpResponse.getOutputStream(), "UTF-8");

            if (!HttpMethod.GET.toString().equals(httpRequest.getMethod())) {
                log.warn("{}: Unsupported method attempted {}", getLogPrefix(), httpRequest.getMethod());
                out.append(makeErrorResponse(HttpStatus.SC_METHOD_NOT_ALLOWED, httpRequest.getMethod() + " not allowed", "Only GET is allowed"));
            } else if (flowInformation != null) {
                final Gson gson = new Gson();
                out.append(gson.toJson(flowInformation));
                httpResponse.setStatus(HttpStatus.SC_OK);
            } else {
                out.append(makeErrorResponse(HttpStatus.SC_NOT_IMPLEMENTED, "Not implemented on the server side", ""));
            }
            out.flush();
        } catch (IOException e) {
            log.error("{}: Could not encode the JSON response", getLogPrefix(), e);
            httpResponse.setStatus(HttpStatus.SC_SERVICE_UNAVAILABLE);
            return ActionSupport.buildEvent(this, EventIds.IO_ERROR);
        }
        return ActionSupport.buildProceedEvent(this);
    }
}
    