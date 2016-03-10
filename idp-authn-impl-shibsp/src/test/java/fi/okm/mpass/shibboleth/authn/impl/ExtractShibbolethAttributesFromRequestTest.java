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

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.okm.mpass.shibboleth.authn.context.ShibbolethAuthnContext;

/**
 * Unit tests for {@link ExtractShibbolethAttributesFromRequest}.
 */
public class ExtractShibbolethAttributesFromRequestTest extends PopulateAuthenticationContextTest {

    /** The action to be tested. */
    private ExtractShibbolethAttributesFromRequest action;

    /** The idp of the context. */
    private String expectedIdp;

    /** The instant of the context. */
    private String expectedInstant;

    /** The contextClass of the context. */
    private String expectedContextClass;

    /** The method of the context. */
    private String expectedMethod;
    
    /** The request attribute. */
    private String expectedAttribute;
    
    /** The HTTP header. */
    private String expectedHeader;
    
    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
    }

    /**
     * Initializes the expected context variables.
     */
    @BeforeTest
    public void initTest() {
        expectedIdp = "mockIdp";
        expectedInstant = "mockInstant";
        expectedContextClass = "mockContextClass";
        expectedMethod = "mockMethod";
        expectedAttribute = "mockAttribute";
        expectedHeader = "mockHeader";
    }

    /**
     * Tests action without {@link HttpServletRequest}.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testNoServlet() throws ComponentInitializationException {
        action = new ExtractShibbolethAttributesFromRequest("");
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Tests successful construction of {@link ShibbolethAuthnContext} with prefix in headers.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testSuccessWithPrefix() throws ComponentInitializationException {
        testSuccess("AJP_");
    }
    
    /**
     * Tests successful construction of {@link ShibbolethAuthnContext} without prefix in headers.
     * 
     * @throws ComponentInitializationException 
     */
    @Test
    public void testSuccessWithoutPrefix() throws ComponentInitializationException {
        testSuccess("");
    }
    
    /**
     * Tests successful construction of {@link ShibbolethAuthnContext}.
     * 
     * @param prefix The prefix for the headers.
     * @throws ComponentInitializationException 
     */
    public void testSuccess(final String prefix) throws ComponentInitializationException {
        action = new ExtractShibbolethAttributesFromRequest(prefix);
        action.setHttpServletRequest(new MockHttpServletRequest());
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethAuthnContext.SHIB_SP_AUTHENTICATION_INSTANT, expectedInstant);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethAuthnContext.SHIB_SP_AUTHENTICATION_METHOD, expectedMethod);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethAuthnContext.SHIB_SP_AUTHN_CONTEXT_CLASS, expectedContextClass);
        ((MockHttpServletRequest) action.getHttpServletRequest())
            .addHeader(prefix + ShibbolethAuthnContext.SHIB_SP_IDENTITY_PROVIDER, expectedIdp);
        ((MockHttpServletRequest) action.getHttpServletRequest()).addHeader(expectedHeader, expectedHeader);
        ((MockHttpServletRequest) action.getHttpServletRequest()).setAttribute(expectedAttribute, expectedAttribute);
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final ShibbolethAuthnContext shibCtx = authCtx.getSubcontext(ShibbolethAuthnContext.class, false);
        Assert.assertNotNull(shibCtx, "No shibboleth context attached");
        Assert.assertEquals(shibCtx.getIdp(), expectedIdp);
        Assert.assertEquals(shibCtx.getInstant(), expectedInstant);
        Assert.assertEquals(shibCtx.getMethod(), expectedMethod);
        Assert.assertEquals(shibCtx.getContextClass(), expectedContextClass);        
        Assert.assertEquals(shibCtx.getAttributes().size(), 1);
        Assert.assertEquals(shibCtx.getAttributes().get(expectedAttribute), expectedAttribute);
        Assert.assertEquals(shibCtx.getHeaders().size(), 1);
        Assert.assertEquals(shibCtx.getHeaders().get(expectedHeader), expectedHeader);
    }
}
