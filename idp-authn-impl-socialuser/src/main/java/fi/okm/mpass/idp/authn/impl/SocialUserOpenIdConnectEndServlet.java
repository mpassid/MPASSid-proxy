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

import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.annotation.WebServlet;
import javax.annotation.Nonnull;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts Social identity and places it in a request attribute to be used by
 * the IdP's external authentication interface.
 */
@WebServlet(name = "SocialUserOpenIdConnectEndServlet", urlPatterns = { "/Authn/SocialUserOpenIdConnectEnd" })
public class SocialUserOpenIdConnectEndServlet extends HttpServlet {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE
     * IMPLEMENTATION.
     */

    /** Serial UID. */
    private static final long serialVersionUID = -3162157736238514852L;

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory
            .getLogger(SocialUserOpenIdConnectEndServlet.class);

    /** Constructor. */
    public SocialUserOpenIdConnectEndServlet() {
    }

    /** {@inheritDoc} */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
    }

    /** {@inheritDoc} */
    @Override
    protected void service(final HttpServletRequest httpRequest,
            final HttpServletResponse httpResponse) throws ServletException,
            IOException {
        log.trace("Entering");
        try {
            String key = (String) httpRequest
                    .getSession()
                    .getAttribute(
                            "fi.okm.mpass.idp.authn.impl.SocialUserOpenIdConnectStartServlet.key");
            SocialUserOpenIdConnectContext socialUserOpenIdConnectContext = (SocialUserOpenIdConnectContext) httpRequest
                    .getSession()
                    .getAttribute(
                            "fi.okm.mpass.idp.authn.impl.SocialUserOpenIdConnectStartServlet.socialUserOpenIdConnectContext");
            log.debug(httpRequest.getRequestURL() + "?"
                    + httpRequest.getQueryString());
            try {
                socialUserOpenIdConnectContext
                        .setAuthenticationResponseURI(httpRequest);
            } catch (URISyntaxException e) {
                // TODO: FIX ERROR VALUE
                log.trace("Leaving");
                return;
            }
            ExternalAuthentication.finishExternalAuthentication(key,
                    httpRequest, httpResponse);
        } catch (ExternalAuthenticationException e) {
            log.error(e.getMessage());
            e.printStackTrace();
        }
        log.trace("Leaving");

    }

}
