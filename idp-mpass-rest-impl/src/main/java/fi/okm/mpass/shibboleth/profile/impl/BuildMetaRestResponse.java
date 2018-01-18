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

import fi.okm.mpass.shibboleth.rest.data.MetaDTO;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This class builds a JSON response corresponding to the attached {@link MetaDTO} object.
 * The JSON is directly to the {@link HttpServletResponse}'s output.
 */
public class BuildMetaRestResponse extends AbstractRestResponseAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BuildMetaRestResponse.class);
    
    /** The proxy meta object to be returned to the client. */
    @Nonnull private MetaDTO metaDTO;

    /** 
     * Get the proxy meta object to be returned to the client.
     * 
     * @return metaDTO.
     */
    public MetaDTO getMetaDTO() {
        return metaDTO;
    }
    
    /**
     * Set the proxy meta object to be returned to the client.
     * 
     * @param newMetaDto The object to set, cannot be null.
     */
    public void setMetaDTO(MetaDTO newMetaDto) {
        metaDTO = Constraint.isNotNull(newMetaDto, "metaDTO cannot be null!");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        log.debug("Initializing");
        super.doInitialize();
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
            } else if (metaDTO != null) {
                final Gson gson = new Gson();
                out.append(gson.toJson(getMetaDTO()));
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
