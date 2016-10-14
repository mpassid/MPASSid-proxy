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

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;

/**
 * A sequence step resolver that expects the result to contain an HTML FORM with defined action URL.
 */
public class FormPostTargetResolver extends BaseSequenceStepResolver {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(FormPostTargetResolver.class);

    /** The automatically parsed FORM parameters. */
    private final List<NameValuePair> parameters;

    /**
     * Constructor.
     * @param clientBuilder The HTTP client builder.
     */
    public FormPostTargetResolver(final HttpClientBuilder clientBuilder) {
        this(clientBuilder, null);
    }
    
    /**
     * Constructor.
     * @param clientBuilder The HTTP client builder.
     * @param initialParams The parameters not existing in the {@link SequenceStep}, but needed for the step.
     */
    public FormPostTargetResolver(final HttpClientBuilder clientBuilder, final List<NameValuePair> initialParams) {
        super(clientBuilder);
        parameters = initialParams;
    }
    
    /** {@inheritDoc} */
    public SequenceStep resolve(final HttpContext context, final SequenceStep startingStep) 
            throws ResponseValidatorException {
        if (parameters != null) {
            log.debug("Adding the step parameters {}", parameters);
            for (final NameValuePair parameter : parameters) {
                startingStep.getParameters().add(parameter);
            }
        }
        final String result = resolveStep(context, startingStep, true);
        final SequenceStep resultStep = new SequenceStep();
        final List<NameValuePair> resultParameters = new ArrayList<>();
        final String action = getValue(result, "action");
        if (getValue(result, "name=\"wa\" value") != null) {
            resultParameters.add(new BasicNameValuePair("wa", 
                    StringEscapeUtils.unescapeHtml(getValue(result, "name=\"wa\" value"))));
        }
        if (getValue(result, "name=\"wresult\" value") != null) {
            resultParameters.add(new BasicNameValuePair("wresult", 
                    StringEscapeUtils.unescapeHtml(getValue(result, "name=\"wresult\" value"))));
        }
        if (getValue(result, "name=\"wctx\" value") != null) {
            resultParameters.add(new BasicNameValuePair("wctx",
                    StringEscapeUtils.unescapeHtml(getValue(result, "name=\"wctx\" value"))));
        }
        if (getValue(result, "name=\"SAMLResponse\" value") != null) {
            resultParameters.add(new BasicNameValuePair("SAMLResponse", 
                    StringEscapeUtils.unescapeHtml(getValue(result, "name=\"SAMLResponse\" value"))));
        }
        if (getValue(result, "name=\"RelayState\" value") != null) {
            resultParameters.add(new BasicNameValuePair("RelayState", 
                    StringEscapeUtils.unescapeHtml(getValue(result, "name=\"RelayState\" value"))));
        }
        if (action != null) {
            resultStep.setUrl(action.replaceAll("&#x3a;", ":").replaceAll("&#x2f;", "/"));
        }
        if (resultParameters.size() > 0) {
            resultStep.setParameters(resultParameters);
        }
        return resultStep;   
    }
}