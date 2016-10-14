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

package fi.okm.mpass.shibboleth.monitor;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * The base {@link SequenceStepResolver} implementation.
 */
public abstract class BaseSequenceStepResolver implements SequenceStepResolver {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(BaseSequenceStepResolver.class);

    /** The builder for HTTP client. */
    private final HttpClientBuilder httpClientBuilder;
    
    /** The validators attached to this resolver. */
    private List<ResponseValidator> validators;
    
    /** The identifier for this resolver. */
    private String id;

    /**
     * Constructor.
     * @param clientBuilder The builder for HTTP client.
     */
    public BaseSequenceStepResolver(final HttpClientBuilder clientBuilder) {
        httpClientBuilder = Constraint.isNotNull(clientBuilder, "clientBuilder cannot be null!");
        validators = new ArrayList<ResponseValidator>();
    }

    /** {@inheritDoc} */
    public List<ResponseValidator> getValidators() {
        return validators;
    }
    
    /** {@inheritDoc} */
    public void addValidator(final ResponseValidator validator) {
        validators.add(validator);
    }
    
    /** {@inheritDoc} */
    public void setValidators(List<ResponseValidator> newValidators) {
        validators = newValidators;
    }
  
    /**
     * Initializes a HTTP client.
     * 
     * @return The HTTP client.
     * @throws ResponseValidatorException If initialization fails for some reason.
     */
    protected HttpClient initializeHttpClient() throws ResponseValidatorException {
        final HttpClient httpClient;
        try {
            httpClient = httpClientBuilder.buildClient();
        } catch (Exception e) {
            log.error("Could not initialize a http client", e);
            throw new ResponseValidatorException(getId() + ": Could not initialize HttpClient!");
        }
        return httpClient;
    }
    
    /**
     * Initializes the HTTP request for the given step.
     * 
     * @param step The SSO sequence step.
     * @return The HTTP request corresponding to the step.
     * @throws ResponseValidatorException If initialization failed for some reason.
     */
    protected HttpUriRequest initializeHttpRequest(final SequenceStep step) throws ResponseValidatorException {
        final HttpUriRequest request;
        if (step.getParameters() == null) {
            request = new HttpGet(step.getUrl());
        } else {
            request = new HttpPost(step.getUrl());
            try {
                ((HttpPost)request).setEntity(new UrlEncodedFormEntity(step.getParameters()));
            } catch (UnsupportedEncodingException e) {
                log.error("Could not encode the given parameters to POST", e);
                throw new ResponseValidatorException(getId() + ": Could not encode the request parameters!");
            }
        }
        return request;
    }
    
    /**
     * Resolves the step.
     * 
     * @param context The context containing for instance cookies.
     * @param step The SSO sequence step starting the resolution.
     * @param followRedirects Whether to automatically follow redirects.
     * @return The resulting step.
     * @throws ResponseValidatorException If validation failed for some reason.
     */
    public String resolveStep(final HttpContext context, final SequenceStep step, final boolean followRedirects) 
            throws ResponseValidatorException {
        final HttpClient httpClient = initializeHttpClient();
        final HttpUriRequest request = initializeHttpRequest(step);
        final HttpResponse response;
        
        try {
            response = httpClient.execute(request, context);
            if (log.isTraceEnabled()) {
                for (final Header header : response.getAllHeaders()) {
                    log.trace("Header: {} = {}", header.getName(), header.getValue());
                }            
            }
            try {
                if (followRedirects && response.getHeaders("Location") != null 
                        && response.getHeaders("Location").length > 0) {
                    final SequenceStep redirectStep = new SequenceStep();
                    final String url = response.getHeaders("Location")[0].getValue();
                    if (!url.contains("://")) {
                        final HttpHost target = (HttpHost) context.getAttribute(
                                HttpCoreContext.HTTP_TARGET_HOST);
                        redirectStep.setUrl(target.getSchemeName() + "://" + target.getHostName() + url);
                    } else {
                        redirectStep.setUrl(url);
                    }
                    return resolveStep(context, redirectStep, followRedirects);
                } else {
                    final String result = EntityUtils.toString(response.getEntity(), "UTF-8");
                    for (final ResponseValidator validator : validators) {
                        validator.validate(response, result);
                    }
                    log.trace("Full contents of the response {}", result);
                    return result;
                }
            } finally {
                EntityUtils.consume(response.getEntity());                
            }
        } catch (IOException e) {
            log.error("Could not perform a http request", e);
            throw new ResponseValidatorException(getId() + ": Could not perform a http request", e);
        }
    }
    
    /** {@inheritDoc} */
    public String getId() {
        return id;
    }
    
    /**
     * Set the identifier for the resolver.
     * 
     * @param newId What to set.
     * @return The identifier for the resolver.
     */
    public String setId(final String newId) {
        id = Constraint.isNotEmpty(newId, "id cannot be null!");
        return id;
    }
    
    /**
     * Get the paramater value from a given query string.
     * 
     * @param string The query string.
     * @param key The parameter key.
     * @return The parameter value, null if does not exist.
     */
    protected String getValue(final String string, final String key) {
        int index = string.indexOf(key + "=\"");
        log.trace("Found index: ", index);
        int offset = index + new String(key + "=\"").length();
        if (index != -1) {
            return string.substring(offset, string.indexOf("\"", offset));
        }
        return null;
    }

    /**
     * Get the parameter value for a given key from a given string. The logic is to find the value -attribute in the
     * same XML element as where the key string is located in quotes.
     * 
     * @param string The source string.
     * @param paramKey The key in quotes.
     * @return The contents of the value attribute, null if does not exist.
     */
    protected String getParamValue(final String string, final String paramKey) {
        int index = string.indexOf("\"" + paramKey + "\"");
        int elementEnd = string.indexOf(">", index);
        final String valueKey = "value=\"";
        int valueStart = string.indexOf(valueKey, index);
        if (valueStart < elementEnd) {
            int offset = valueStart + new String(valueKey).length();
            return string.substring(offset, string.indexOf("\"", offset));
        }
        return null;
    }
}
