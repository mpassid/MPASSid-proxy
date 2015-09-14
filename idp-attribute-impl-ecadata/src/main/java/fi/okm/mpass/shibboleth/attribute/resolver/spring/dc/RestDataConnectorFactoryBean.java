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

package fi.okm.mpass.shibboleth.attribute.resolver.spring.dc;

import fi.okm.mpass.shibboleth.attribute.resolver.dc.impl.RestDataConnector;
import net.shibboleth.ext.spring.factory.AbstractComponentAwareFactoryBean;

/**
 * A Factory bean to summon up {@link RestDataConnector} from supplied attributes.
 */
@SuppressWarnings("rawtypes")
public class RestDataConnectorFactoryBean extends AbstractComponentAwareFactoryBean {

    /** The endpoint URL for the ECA Data API. */
    private String endpointUrl;

    /** The attribute ID used as a hook. */
    private String hookAttribute;

    /** The Identity Provider ID corresponding to the hook. */
    private String idpId;

    /** The result attribute ID of the resolved person ID. */
    private String resultAttribute;

    /** The token used for authenticating to ECA Data API. */
    private String token;

    /** Whether to disregard TLS certificate validation of the endpoint. */
    private String disregardTLSCertificate;

    /** {@inheritDoc} */
    @Override
    public Class<?> getObjectType() {
        return RestDataConnector.class;
    }

    /** {@inheritDoc} */
    @Override
    protected RestDataConnector doCreateInstance() throws Exception {
        RestDataConnector dataConnector = new RestDataConnector();
        dataConnector.setEndpointUrl(getEndpointUrl());
        dataConnector.setHookAttribute(getHookAttribute());
        dataConnector.setIdpId(getIdpId());
        dataConnector.setResultAttribute(getResultAttribute());
        dataConnector.setToken(getToken());
        dataConnector.setDisregardTLSCertificate("true".equalsIgnoreCase(getDisregardTLSCertificate()));
        return dataConnector;
    }

    /**
     * Get the endpoint URL.
     * @return endpointUrl.
     */
    public String getEndpointUrl() {
        return endpointUrl;
    }

    /**
     * Set the endpoint URL.
     * @param url What to set.
     */
    public void setEndpointUrl(String url) {
        this.endpointUrl = url;
    }

    /**
     * Get the hook attribute.
     * @return hookAttribute.
     */
    public String getHookAttribute() {
        return hookAttribute;
    }

    /**
     * Set the hook attribute.
     * @param attribute What to set.
     */
    public void setHookAttribute(String attribute) {
        this.hookAttribute = attribute;
    }

    /**
     * Get the Identity Provider ID.
     * @return idpId.
     */
    public String getIdpId() {
        return idpId;
    }

    /**
     * Set the Identity Provider ID.
     * @param id What to set.
     */
    public void setIdpId(String id) {
        this.idpId = id;
    }

    /**
     * Get the result attribute ID.
     * @return resultAttribute.
     */
    public String getResultAttribute() {
        return resultAttribute;
    }

    /**
     * Set the result attribute ID.
     * @param attribute What to set.
     */
    public void setResultAttribute(String attribute) {
        this.resultAttribute = attribute;
    }

    /**
     * Get the authorization token.
     * @return token.
     */
    public String getToken() {
        return token;
    }

    /**
     * Set the authorization token.
     * @param authzToken What to set.
     */
    public void setToken(String authzToken) {
        this.token = authzToken;
    }

    /**
     * Get whether to disregard endpoint certificate validation.
     * @return disregardTLSCertificate.
     */
    public String getDisregardTLSCertificate() {
        return disregardTLSCertificate;
    }

    /**
     * Set whether to disregard endpoint certification validation.
     * @param disregardCertificate What to set.
     */
    public void setDisregardTLSCertificate(String disregardCertificate) {
        this.disregardTLSCertificate = disregardCertificate;
    }
}
