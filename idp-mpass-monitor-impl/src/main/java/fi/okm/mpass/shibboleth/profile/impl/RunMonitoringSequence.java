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

import java.util.List;

import javax.annotation.Nonnull;

import org.apache.http.client.CookieStore;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.protocol.HttpContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.shibboleth.monitor.ResponseValidatorException;
import fi.okm.mpass.shibboleth.monitor.SequenceStep;
import fi.okm.mpass.shibboleth.monitor.SequenceStepResolver;
import fi.okm.mpass.shibboleth.monitor.context.MonitoringResultContext;
import fi.okm.mpass.shibboleth.monitor.context.MonitoringSequenceResult;
import fi.okm.mpass.shibboleth.monitor.context.MonitoringSequenceStepResult;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This actions runs the attached {@link SequenceStepResolver}s.
 */
@SuppressWarnings("rawtypes")
public class RunMonitoringSequence extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(RunMonitoringSequence.class);

    /** The list of attached resolvers. */
    private List<SequenceStepResolver> resolvers;
    
    /** The initial URL for the initial monitoring step. */
    @Nonnull @NotEmpty private String initialUrl;
    
    /**
     * Set the list of attached resolvers.
     * @param newResolvers What to set.
     */
    public void setResolvers(List<SequenceStepResolver> newResolvers) {
        resolvers = newResolvers;
    }
    
    /**
     * Set the initial URL for the initial monitoring step.
     * @param url What to set.
     */
    public void setInitialUrl(final String url) {
        initialUrl = Constraint.isNotEmpty(url, "The initial URL cannot be empty");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        log.debug("Initializing");
        super.doInitialize();
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(
            @Nonnull final ProfileRequestContext profileRequestContext) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        final MonitoringResultContext monitoringCtx = 
                profileRequestContext.getSubcontext(MonitoringResultContext.class, true);
        
        final HttpContext context = HttpClientContext.create();
        final CookieStore cookieStore = new BasicCookieStore();
        context.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);
        int i = 0;
        final MonitoringSequenceResult seqResult = new MonitoringSequenceResult();
        seqResult.setStartTime(System.currentTimeMillis());
        SequenceStep initial = new SequenceStep();
        initial.setUrl(initialUrl);
        for (final SequenceStepResolver resolver : resolvers) {
            final MonitoringSequenceStepResult stepResult = new MonitoringSequenceStepResult();
            stepResult.setStartTime(System.currentTimeMillis());
            stepResult.setId(resolver.getId());
            i++;
            log.debug("Performing step {} : {}", i, initial.toString());
            try {
                initial = resolver.resolve(context, initial);
            } catch (ResponseValidatorException e) {
                log.warn("Response validation failed", e);
                stepResult.setErrorMessage(e.getMessage());
                stepResult.setEndTime(System.currentTimeMillis());
                seqResult.addStepResult(stepResult);
                break;
            }
            stepResult.setEndTime(System.currentTimeMillis());
            seqResult.addStepResult(stepResult);
        }
        seqResult.setEndTime(System.currentTimeMillis());
        monitoringCtx.addResult(seqResult);
    }
}