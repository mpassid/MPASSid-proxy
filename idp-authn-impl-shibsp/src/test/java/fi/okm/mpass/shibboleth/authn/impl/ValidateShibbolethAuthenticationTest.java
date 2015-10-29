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

import javax.security.auth.Subject;

import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.okm.mpass.shibboleth.authn.context.ShibbolethAuthnContext;
import fi.okm.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipal;
import fi.okm.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateShibbolethAuthentication}.
 */
public class ValidateShibbolethAuthenticationTest extends PopulateAuthenticationContextTest {
    
    /** The action to be tested. */
    private ValidateShibbolethAuthentication action;
    
    /** The configuration for the attribute containing username. */
    private String uidConfig;
    
    /** The attribute containing username. */
    private String uid;
    
    /** The value of the username. */
    private String uidValue;
    
    /** {@inheritDoc} */
    @BeforeMethod public void setUp() throws Exception {
        super.setUp();
        uidConfig = "username,username2";
        uid = "username";
        uidValue = "mockUser";
        action = new ValidateShibbolethAuthentication();
        action.setUsernameAttribute(uidConfig);
        action.setPopulateAttributes(true);
        action.initialize();
    }

    /**
     * Runs action without attempted flow.
     */
    @Test public void testMissingFlow() {
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }
    
    /**
     * Runs action without {@link ShibbolethAuthnContext}.
     */
    @Test public void testMissingContext() {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_AUTHN_CTX);
    }

    /**
     * Runs action without username attribute.
     */
    @Test public void testMissingUser() {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethAuthnContext shibContext = prc.getSubcontext(AuthenticationContext.class, false)
                .getSubcontext(ShibbolethAuthnContext.class, true);
        Assert.assertNotNull(shibContext);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }
    
    /**
     * Runs action with username in attribute map.
     */
    @Test public void testAttribute() {
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class, false);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethAuthnContext shibContext = prc.getSubcontext(AuthenticationContext.class, false)
                .getSubcontext(ShibbolethAuthnContext.class, true);
        Assert.assertNotNull(shibContext);
        shibContext.getAttributes().put(uid, uidValue);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(ac.getAuthenticationResult());
        final Subject subject = ac.getAuthenticationResult().getSubject();
        Assert.assertEquals(subject.getPrincipals(UsernamePrincipal.class).iterator().next().getName(), uidValue);   
        Assert.assertEquals(subject.getPrincipals(ShibHeaderPrincipal.class).iterator().hasNext(), false);
        final ShibAttributePrincipal principal = subject.getPrincipals(ShibAttributePrincipal.class).iterator().next();
        Assert.assertEquals(principal.getValue(), uidValue);
    }
    
    /**
     * Runs action with username in HTTP headers map.
     */
    @Test public void testHeader() {
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class, false);
        ac.setAttemptedFlow(authenticationFlows.get(0));
        final ShibbolethAuthnContext shibContext = prc.getSubcontext(AuthenticationContext.class, false)
                .getSubcontext(ShibbolethAuthnContext.class, true);
        Assert.assertNotNull(shibContext);
        shibContext.getHeaders().put(uid, uidValue);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(ac.getAuthenticationResult());
        final Subject subject = ac.getAuthenticationResult().getSubject();
        Assert.assertEquals(subject.getPrincipals(UsernamePrincipal.class).iterator().next().getName(), uidValue);   
        Assert.assertEquals(subject.getPrincipals(ShibHeaderPrincipal.class).iterator().hasNext(), false);
        Assert.assertEquals(subject.getPrincipals(ShibAttributePrincipal.class).iterator().hasNext(), false);
    }
}