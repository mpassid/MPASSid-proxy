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

import java.security.Principal;
import java.util.Collection;

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link AuthnFlowIdAuditExtractor}.
 */
public class AuthnFlowIdAuditExtractorTest {
    
    /** The authentication flow id whose value is extracted. */
    protected String authnFlowId;
    
    /** The request context containing the profile context. */
    protected RequestContext src;
    
    /** The profile context containing the authentication context. */
    protected ProfileRequestContext<?, ?> prc;
    
    /** The extractor to be tested. */
    protected AuthnFlowIdAuditExtractor authnFlowIdExtractor;
    
    /**
     * Configures the variables needed in testing.
     */
    @BeforeTest public void setupTest() {
        authnFlowId = "mockFlowId";
        authnFlowIdExtractor = new AuthnFlowIdAuditExtractor();
    }
    
    /**
     * Populates the request context together with its relevant subcontexts.
     * 
     * @throws ComponentInitializationException If the contexts cannot be initialized.
     */
    @BeforeMethod public void populateContext() throws ComponentInitializationException {        
        src = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(src);
    }
    
    /**
     * Verifies that the construction fails with null function.
     */
    @Test public void initNullFunction() {
        boolean catched = false;
        try {
            authnFlowIdExtractor = new AuthnFlowIdAuditExtractor(null);
        } catch (ConstraintViolationException e) {
            catched = true;
        }
        Assert.assertTrue(catched);
    }
    
    /**
     * Tests extractor without {@link AuthenticationContext}.
     */
    @Test public void testNoContext() {
        Collection<String> result = authnFlowIdExtractor.apply(prc);
        Assert.assertEquals(result.size(), 0);
    }
    
    /**
     * Tests extractor without {@link AuthenticationResult}.
     */
    @Test public void testNoResult() {
        prc.getSubcontext(AuthenticationContext.class, true);
        Collection<String> result = authnFlowIdExtractor.apply(prc);
        Assert.assertEquals(result.size(), 0);        
    }
    
    /**
     * Tests extractor with fulfilled prerequisites.
     */
    @Test public void testResult() {
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, true);
        final Principal principal = new UsernamePrincipal("mockUser");
        final AuthenticationResult authnResult = new AuthenticationResult(authnFlowId, principal);
        authnContext.setAuthenticationResult(authnResult);
        Collection<String> result = authnFlowIdExtractor.apply(prc);
        Assert.assertEquals(result.size(), 1);
        Assert.assertEquals(result.iterator().next(), authnFlowId);
    }
}
