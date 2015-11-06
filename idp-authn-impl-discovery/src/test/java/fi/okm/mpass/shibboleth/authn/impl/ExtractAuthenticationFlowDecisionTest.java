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

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ExtractAuthenticationFlowDecision}.
 */
public class ExtractAuthenticationFlowDecisionTest extends PopulateAuthenticationContextTest {

    /** The action to be tested. */
    private ExtractAuthenticationFlowDecision action;

    /** The authentication flow field name coming from UI. */
    private String authnFlowField;

    /** The authentication flow decision. */
    private String authnFlowDecision;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        authnFlowField = "mockAuthnFlowField";
        authnFlowDecision = "mockDecision";
        action = new ExtractAuthenticationFlowDecision();
        action.setAuthnFlowFieldName(authnFlowField);
        action.setHttpServletRequest(new MockHttpServletRequest());
        action.initialize();
    }

    /**
     * Runs the action with invalid input.
     */
    @Test
    public void testNoDecision() {
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.REQUEST_UNSUPPORTED);
    }

    /**
     * Runs the action with valid input.
     */
    @Test
    public void testValid() {
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnFlowField, authnFlowDecision);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.RESELECT_FLOW);
        AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        Assert.assertNotNull(authCtx);
        Assert.assertEquals(authCtx.getSignaledFlowId(), authnFlowDecision);
    }
}
