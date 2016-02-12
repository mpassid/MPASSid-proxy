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

package fi.okm.mpass.shibboleth.attribute.resolver.dc.impl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

import fi.okm.mpass.shibboleth.attribute.resolver.data.UserDTO;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AbstractDataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.ResolvedAttributeDefinition;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * This class implements a {@link DataConnector} (resolver plugin) that communicates with ECA user data API
 * for resolving OID using IdP ID and ECA Authn ID.
 *
 * Example configuration (in attribute-resolver.xml):
 *
 * <resolver:DataConnector id="calculateAuthnId" xsi:type="ecaid:AuthnIdDataConnector" srcAttributeNames="uid"
 * destAttributeName="authnid"/> 
 */
public class RestDataConnector extends AbstractDataConnector {
    
    /** The attribute id for the username. */
    public static final String ATTR_ID_USERNAME = "username";
    
    /** The attribute id for the first name. */
    public static final String ATTR_ID_FIRSTNAME = "firstName";
    
    /** The attribute id for the last name. */
    public static final String ATTR_ID_SURNAME = "surname";
    
    /** The attribute id for the roles. */
    public static final String ATTR_ID_ROLES = "roles";
    
    /** The attribute id for the municipalities. */
    public static final String ATTR_ID_MUNICIPALITIES = "municipalities";
    
    /** The attribute id for the groups. */
    public static final String ATTR_ID_GROUPS = "groups";
    
    /** The attribute id for the schools. */
    public static final String ATTR_ID_SCHOOLS = "schools";
    
    /** The attribute id for the structured roles. */
    public static final String ATTR_ID_STRUCTURED_ROLES = "structuredRoles";

    /** Class logging. */
    private final Logger log = LoggerFactory.getLogger(RestDataConnector.class);

    /** The endpoint URL for the REST server. */
    private String endpointUrl;

    /** The attribute used for hooking the user object from the REST server. */
    private String hookAttribute;

    /** The attribute id containing the ECA IdP id. */
    private String idpId;

    /** The attribute id prefix for the resulting attributes. */
    private String resultAttributePrefix;

    /** The token used for authenticating to the REST server. */
    private String token;

    /** The {@link HttpClientBuilder} used for constructing HTTP clients. */
    private HttpClientBuilder httpClientBuilder;

    /**
     * Constructor.
     */
    public RestDataConnector() {
        this(null);
    }
    
    /**
     * Constructor.
     * @param clientBuilder The {@link HttpClientBuilder} used for constructing HTTP clients.
     */
    public RestDataConnector(HttpClientBuilder clientBuilder) {
        super();
        if (clientBuilder == null) {
            httpClientBuilder = new HttpClientBuilder();
        } else {
            httpClientBuilder = clientBuilder;
        }
    }

    /** {@inheritDoc} */
    @Nullable @Override protected Map<String, IdPAttribute> doDataConnectorResolve(
            @Nonnull final AttributeResolutionContext attributeResolutionContext,
            @Nonnull final AttributeResolverWorkContext attributeResolverWorkContext) throws ResolutionException {
        final Map<String, IdPAttribute> attributes = new HashMap<>();

        log.debug("Calling {} for resolving attributes", endpointUrl);

        String attributeCallUrl = endpointUrl;
        String authnIdValue = collectSingleAttributeValue(attributeResolverWorkContext.
                getResolvedIdPAttributeDefinitions(), hookAttribute);
        log.debug("AuthnID before URL encoding = {}", authnIdValue);
        if (authnIdValue == null) {
            log.error("Could not resolve hookAttribute value");
            throw new ResolutionException("Could not resolve hookAttribute value");
        }
        try {
            authnIdValue = URLEncoder.encode(collectSingleAttributeValue(
                    attributeResolverWorkContext.getResolvedIdPAttributeDefinitions(), hookAttribute), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error("Could not use UTF-8 for encoding authnID");
            throw new ResolutionException("Could not use UTF-8 for encoding authnID", e);
        }
        log.debug("AuthnID after URL encoding = {}", authnIdValue);
        final String idpIdValue =
                collectSingleAttributeValue(attributeResolverWorkContext.getResolvedIdPAttributeDefinitions(), idpId);
        attributeCallUrl = attributeCallUrl + "?" + idpIdValue + "=" + authnIdValue;

        HttpEntity restEntity = null;

        try {
            final HttpClient httpClient = getHttpClientBuilder().buildClient();
            log.debug("Calling URL {}", attributeCallUrl);
            final HttpGet getMethod = new HttpGet(attributeCallUrl);
            final HttpContext context = HttpClientContext.create();
            getMethod.addHeader("Authorization", "Token " + token);
            final HttpResponse restResponse = httpClient.execute(getMethod, context);
            final int status = restResponse.getStatusLine().getStatusCode();
            restEntity = restResponse.getEntity();
            log.debug("Response code from Data: HTTP " + status);
            
            if (log.isTraceEnabled()) {
                if (restResponse.getAllHeaders() != null) {
                    for (Header header : restResponse.getAllHeaders()) {
                        log.trace("Header {}: {}", header.getName(), header.getValue());
                    }
                }
            }
            
            final String restResponseStr = EntityUtils.toString(restEntity, "UTF-8");
            log.trace("Response {}", restResponseStr);
            if (status == HttpStatus.SC_OK) {
                final Gson gson = new Gson();
                final UserDTO ecaUser = gson.fromJson(restResponseStr, UserDTO.class);
                populateAttributes(attributes, ecaUser);
                log.debug("{} attributes are now populated", attributes.size());
            } else {
                log.warn("No attributes found for session, http status {}", status);
            }
        } catch (Exception e) {
            log.error("Error in connection to Data API", e);
        } finally {
            EntityUtils.consumeQuietly(restEntity);
        }
        return attributes;
    }
    
    /**
     * Populates the attributes from the given user object to the given result map.
     * 
     * @param attributes The result map of attributes.
     * @param ecaUser The source user object.
     */
    protected void populateAttributes(final Map<String, IdPAttribute> attributes, UserDTO ecaUser) {
        populateAttribute(attributes, ATTR_ID_USERNAME, ecaUser.getUsername());
        populateAttribute(attributes, ATTR_ID_FIRSTNAME, ecaUser.getFirstName());
        populateAttribute(attributes, ATTR_ID_SURNAME, ecaUser.getLastName());
        if (ecaUser.getRoles() != null) {
            for (int i = 0; i < ecaUser.getRoles().length; i++) {
                populateAttribute(attributes, ATTR_ID_SCHOOLS, ecaUser.getRoles()[i].getSchool());
                populateAttribute(attributes, ATTR_ID_GROUPS, ecaUser.getRoles()[i].getGroup());
                populateAttribute(attributes, ATTR_ID_ROLES, ecaUser.getRoles()[i].getRole());
                populateAttribute(attributes, ATTR_ID_MUNICIPALITIES, ecaUser.getRoles()[i].getMunicipality());
                populateStructuredRole(attributes, ecaUser.getRoles()[i]);
            }
        }
    }

    /**
     * Populates an attribute containing a structured role information from the given object. The value is
     * populated to the given map, or appended to its values if the attribute already exists.
     * 
     * @param attributes The result map of attributes.
     * @param role The role object whose values are added.
     */
    protected void populateStructuredRole(final Map<String, IdPAttribute> attributes, final UserDTO.RolesDTO role) {
        final String school = role.getSchool() != null ? role.getSchool() : "";
        final String group = role.getGroup() != null ? role.getGroup() : "";
        final String aRole = role.getRole() != null ? role.getRole() : "";
        final String municipality = role.getMunicipality() != null ? role.getMunicipality() : "";
        final String structuredRole = municipality + ";" + school + ";" + group + ";" + aRole;
        populateAttribute(attributes, ATTR_ID_STRUCTURED_ROLES, structuredRole);
    }
    
    /**
     * Populates an attribute with the the given id and value to the given result map. If the id already
     * exists, the value will be appended to its values.
     * 
     * @param attributes The result map of attributes.
     * @param attributeId The attribute id.
     * @param attributeValue The attribute value.
     */
    protected void populateAttribute(final Map<String, IdPAttribute> attributes, 
            final String attributeId, final String attributeValue) {
        if (StringSupport.trimOrNull(attributeId) == null || StringSupport.trimOrNull(attributeValue) == null) {
            log.debug("Ignoring attirbute {}, null value", attributeId);
            return;
        }
        if (attributes.get(resultAttributePrefix + attributeId) != null) {
            final IdPAttribute idpAttribute = attributes.get(resultAttributePrefix + attributeId);
            idpAttribute.getValues().add(new StringAttributeValue(attributeValue));
            log.debug("Added value {} to attribute {}", attributeValue, resultAttributePrefix + attributeId);
        } else {
            final IdPAttribute idpAttribute = new IdPAttribute(resultAttributePrefix + attributeId);
            final List<IdPAttributeValue<String>> values = new ArrayList<>();
            values.add(new StringAttributeValue(attributeValue));
            idpAttribute.setValues(values);
            attributes.put(resultAttributePrefix + attributeId, idpAttribute);
            log.debug("Populated {} with value {}", resultAttributePrefix + attributeId, attributeValue);
        }
    }

    /**
     * Sets the endpoint URL for the REST server.
     * @param url The endpointUrl.
     */
    public void setEndpointUrl(String url) {
        this.endpointUrl = Constraint.isNotEmpty(url, "The endpoint URL cannot be empty!");
    }
    
    /**
     * Gets the endpoint URL for the REST server.
     * @return The endpointUrl.
     */
    public String getEndpointUrl() {
        return this.endpointUrl;
    }

    /**
     * Sets the attribute used for hooking the user object from the REST server.
     * @param attribute The hookAttribute.
     */
    public void setHookAttribute(String attribute) {
        this.hookAttribute = Constraint.isNotEmpty(attribute, "The hookAttribute cannot be empty!");
    }
    
    /**
     * Gets the attribute used for hooking the user object from the REST server.
     * @return The hookAttribute.
     */
    public String getHookAttribute() {
        return this.hookAttribute;
    }

    /**
     * Sets the attribute id containing the ECA IdP id.
     * @param id The idpId.
     */
    public void setIdpId(String id) {
        this.idpId = Constraint.isNotEmpty(id, "The idpId attribute cannot be empty!");
    }
    
    
    /**
     * Gets the attribute id containing the ECA IdP id.
     * @return The idpId.
     */
    public String getIdpId() {
        return this.idpId;
    }

    /**
     * Sets the attribute id prefix for the resulting attributes. 
     * @param attributePrefix The resultAttributePrefix.
     */
    public void setResultAttributePrefix(String attributePrefix) {
        this.resultAttributePrefix = attributePrefix;
    }
    
    /**
     * Gets the attribute id prefix for the resulting attributes.
     * @return The resultAttributePrefix.
     */
    public String getResultAttributePrefix() {
        return this.resultAttributePrefix;
    }

    /**
     * Sets the token used for authenticating to the REST server.
     * @param authzToken The token.
     */
    public void setToken(String authzToken) {
        this.token = Constraint.isNotEmpty(authzToken, "The token cannot be empty!");
    }
    
    /**
     * Gets the token used for authenticating to the REST server.
     * @return The token.
     */
    public String getToken() {
        return this.token;
    }

    /**
     * Sets whether to disregard the TLS certificate protecting the endpoint URL.
     * @param disregard The flag to disregard the certificate.
     */
    public void setDisregardTLSCertificate(boolean disregard) {
        if (disregard) {
            log.warn("Disregarding TLS certificate in the communication with the REST server!");
        }
        httpClientBuilder.setConnectionDisregardTLSCertificate(disregard);
    }
    
    /**
     * Gets whether to disregard the TLS certificate protecting the endpoint URL.
     * @return true if disregarding, false otherwise.
     */
    public boolean isDisregardTLSCertificate() {
        return httpClientBuilder.isConnectionDisregardTLSCertificate();
    }

    /**
     * Helper method for collecting single attribute value from the map of attribute definitions.
     * @param attributeDefinitions The map of {@link ResolvedAttributeDefinition}s.
     * @param attributeId The attribute id whose single value is collected.
     * @return The single value, null if no or multiple values exist.
     */
    protected String collectSingleAttributeValue(
            @Nonnull final Map<String, ResolvedAttributeDefinition> attributeDefinitions,
            @Nonnull @NotEmpty final String attributeId) {
        final ResolvedAttributeDefinition definition = attributeDefinitions.get(attributeId);
        if (definition == null || definition.getResolvedAttribute() == null) {
            log.warn("Could not find an attribute {} from the context", attributeId);
        } else {
            final List<IdPAttributeValue<?>> values = definition.getResolvedAttribute().getValues();
            if (values.size() == 0) {
                log.warn("No value found for the attribute {}", attributeId);
            } else if (values.size() > 1) {
                log.warn("Multiple values found for the attribute {}, all ignored", attributeId);
            } else {
                log.debug("Found a single value for the attribute {}", attributeId);
                return (String) values.get(0).getValue();
            }
        }
        return null;
    }
    
    /**
     * Returns the current {@link HttpClientBuilder}.
     * @return httpClientBuilder.
     */
    protected HttpClientBuilder getHttpClientBuilder() {
        return httpClientBuilder;
    }
}
