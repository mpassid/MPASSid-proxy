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

package fi.okm.mpass.idp.authn.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.okm.mpass.idp.authn.principal.SocialUserPrincipal;

public class AbstractOAuth2IdentityTest {

    private AbstractOAuth2Identity abstractOAuth2Identity;
    private boolean prin1Match;
    private boolean prin2Match;
    private boolean prin3Match;

    @BeforeMethod
    public void setUp() throws Exception {
        abstractOAuth2Identity = new OAuth2Identity();
        Map<String, String> oauth2PrincipalsDefaults = new HashMap<String, String>();
        oauth2PrincipalsDefaults.put("principal1", "value1");
        oauth2PrincipalsDefaults.put("principal2", "value2");
        oauth2PrincipalsDefaults.put("principal3", "value3");
        abstractOAuth2Identity.setPrincipalsDefaults(oauth2PrincipalsDefaults);
    }

    private void performMatch(Subject subject) {
        prin1Match = false;
        prin2Match = false;
        prin3Match = false;
        final Set<SocialUserPrincipal> principals = subject
                .getPrincipals(SocialUserPrincipal.class);
        for (SocialUserPrincipal sprin : principals) {
            if ("principal1".equals(sprin.getType())
                    && "value1".equals(sprin.getValue())) {
                prin1Match = true;
            }
            if ("principal2".equals(sprin.getType())
                    && "value2".equals(sprin.getValue())) {
                prin2Match = true;
            }
            if ("principal3".equals(sprin.getType())
                    && "value3".equals(sprin.getValue())) {
                prin3Match = true;
            }
        }
    }

    @Test
    public void testDefaultsEmptySubject() throws Exception {
        Subject subject = new Subject();
        abstractOAuth2Identity.addDefaultPrincipals(subject);
        performMatch(subject);
        Assert.assertEquals(subject.getPrincipals().size(), 3);
        Assert.assertEquals(prin1Match, true);
        Assert.assertEquals(prin2Match, true);
        Assert.assertEquals(prin3Match, true);
    }

    @Test
    public void testDefaultsNonEmptySubject() throws Exception {
        Subject subject = new Subject();
        SocialUserPrincipal suPrincipal1 = new SocialUserPrincipal(
                "principalNoMatch", "valueNoMatch");
        SocialUserPrincipal suPrincipal2 = new SocialUserPrincipal(
                "principal1", "value1");
        SocialUserPrincipal suPrincipal3 = new SocialUserPrincipal(
                "principal2", "value2NoMatch");
        subject.getPrincipals().add(suPrincipal1);
        subject.getPrincipals().add(suPrincipal2);
        subject.getPrincipals().add(suPrincipal3);
        abstractOAuth2Identity.addDefaultPrincipals(subject);
        performMatch(subject);
        Assert.assertEquals(subject.getPrincipals().size(), 4);
        Assert.assertEquals(prin1Match, true);
        Assert.assertEquals(prin2Match, false);
        Assert.assertEquals(prin3Match, true);
    }

}
