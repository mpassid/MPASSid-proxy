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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class OpenIdConnectIdentityTest {

    private OpenIdConnectIdentity openIdConnectIdentity;
    private String client_id = "client_id_123";
    private String authorize_endpoint = "https://testsite123.com/authorize";
    private String auth_client_server = "mockclient.test.com";
    private String auth_client_uri = "/auth";

    @BeforeMethod
    public void setUp() throws Exception {
        openIdConnectIdentity = new OpenIdConnectIdentity();
        openIdConnectIdentity.init();
        openIdConnectIdentity.setClientId(client_id);

    }

    @Test
    public void failNoServletGetRedirect() throws Exception {
        Assert.assertNull(openIdConnectIdentity.getRedirectUrl(null));
    }

    @Test
    public void failNoAuthorizeEndpointGetRedirect() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getRequest();
        Assert.assertNull(openIdConnectIdentity
                .getRedirectUrl(mockHttpServletRequest));
    }

    @Test
    public void successGetRedirect() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getRequest();
        openIdConnectIdentity.setAuthorizationEndpoint(authorize_endpoint);
        String redirectUrl = openIdConnectIdentity
                .getRedirectUrl(mockHttpServletRequest);
        Assert.assertNotNull(redirectUrl);
        Assert.assertEquals(verifyUrl(redirectUrl), true);
        List<NameValuePair> params = URLEncodedUtils.parse(
                new URI(redirectUrl), "UTF-8");
        Assert.assertNotNull(params.contains("scope"));
        Assert.assertNotNull(params.contains("response_type"));
        Assert.assertNotNull(params.contains("client_id"));
        Assert.assertNotNull(params.contains("redirect_uri"));
        Assert.assertNotNull(params.contains("state"));
        for (NameValuePair param : params) {
            if (param.getName().equals("scope")) {
                Assert.assertEquals(param.getValue(), "openid");
            }
            if (param.getName().equals("response_type")) {
                Assert.assertEquals(param.getValue(), "code");
            }
            if (param.getName().equals("client_id")) {
                Assert.assertEquals(param.getValue(), client_id);
            }
            if (param.getName().equals("redirect_uri")) {
                Assert.assertEquals(param.getValue(), mockHttpServletRequest
                        .getRequestURL().toString());
            }
        }

    }

    private MockHttpServletRequest getRequest() {
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setProtocol("https");
        mockHttpServletRequest.setServerName(auth_client_server);
        mockHttpServletRequest.setRequestURI(auth_client_uri);
        return mockHttpServletRequest;
    }

    private boolean verifyUrl(String urlString) {
        try {
            new URL(urlString);
        } catch (MalformedURLException e) {
            return false;
        }
        return true;
    }

}
