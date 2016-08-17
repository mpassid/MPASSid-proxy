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

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.idp.saml.impl.TestSources;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.okm.mpass.shibboleth.attribute.resolver.data.UserDTO;
import fi.okm.mpass.shibboleth.attribute.resolver.data.UserDTO.RolesDTO;
import fi.okm.mpass.shibboleth.attribute.resolver.spring.dc.RestDataConnectorParserTest;

/**
 * Unit tests for {@link RestDataConnector}.
 */
public class RestDataConnectorTest {

    /** The expected data connector id. */
    private String expectedId;

    /** The expected endpointUrl value. */
    private String expectedEndpointUrl;

    /** The expected hookAttribute value. */
    private String expectedHookAttribute;

    /** The expected idpId value. */
    private String expectedIdpId;

    /** The expected resultAttribute value. */
    private String expectedResultAttribute;

    /** The expected token value. */
    private String expectedToken;

    /** The expected resolved OID after successful resolution. */
    private String expectedOid;

    /**
     * Initialize unit tests.
     */
    @BeforeMethod
    public void init() {
        expectedId = "restdc";
        expectedEndpointUrl = "testindEndpointUrl";
        expectedHookAttribute = "testingHookAttribute";
        expectedIdpId = "testingIdpId";
        expectedResultAttribute = "username";
        expectedToken = "testingToken";
        expectedOid = "OID1";
    }
    
    /**
     * Tests constructor.
     */
    @Test public void testConstructor() {
        final HttpClientBuilder builder = new HttpClientBuilder();
        Assert.assertEquals(new RestDataConnector(builder).getHttpClientBuilder(), builder);
        Assert.assertNotNull(new RestDataConnector().getHttpClientBuilder());
    }
    
    /**
     * Tests populateAttribute.
     */
    @Test public void testPopulateAttribute() {
        final RestDataConnector dataConnector = new RestDataConnector();
        dataConnector.setResultAttributePrefix("");        
        final Map<String, IdPAttribute> attributes = new HashMap<>();
        final String name = "mock";
        final String value = "mockValue";
        dataConnector.populateAttribute(attributes, (String)null, (String)null);
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, "", (String)null);
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, name, (String)null);
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, name, "");
        Assert.assertTrue(attributes.isEmpty());
        dataConnector.populateAttribute(attributes, name, value);
        Assert.assertEquals(attributes.size(), 1);
        Assert.assertEquals(attributes.get(name).getValues().size(), 1);
        Assert.assertEquals(attributes.get(name).getValues().get(0).getValue(), value);
    }
    
    /**
     * Tests populateStructuredRole.
     */
    @Test public void testPopulateStructuredRole() {
        final UserDTO user = new UserDTO();
        final RolesDTO role = user.new RolesDTO();
        final Map<String, IdPAttribute> attributes = new HashMap<>();
        final RestDataConnector dataConnector = new RestDataConnector();
        dataConnector.setResultAttributePrefix("");
        dataConnector.populateStructuredRole(attributes, role);
        final IdPAttribute attribute = attributes.get(RestDataConnector.ATTR_ID_STRUCTURED_ROLES);
        Assert.assertNotNull(attribute);
        Assert.assertEquals(attribute.getValues().size(), 1);
        Assert.assertEquals(attribute.getValues().get(0).getValue(), ";;;");
    }
    
    /**
     * Tests {@link RestDataConnector} with minimum configuration, with empty authnId value.
     */
    @Test
    public void testNoAuthnId() throws Exception {
        expectedHookAttribute = "invalid"; // differs from the configuration
        boolean catched = false;
        try {
            final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-0role-0attr.json", 
                    "restdc-min.xml");
        } catch (ResolutionException e) {
            catched = true;
        }
        Assert.assertTrue(catched);
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration, with empty idpId value.
     */
    @Test
    public void testNoIdpId() throws Exception {
        expectedIdpId = "invalid"; // differs from the configuration
        boolean catched = false;
        try {
            final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-0role-0attr.json", 
                    "restdc-min.xml");
        } catch (ResolutionException e) {
            catched = true;
        }
        Assert.assertTrue(catched);
    }
    /**
     * Tests {@link RestDataConnector} with minimum configuration, without roles for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testDefaultNoRoles() throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-0role-0attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 3);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration, with 1 role for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testDefaultOneRole() throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-1role-1attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 9);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration, with two roles for the user.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testDefaultTwoRoles() throws ComponentInitializationException, ResolutionException, Exception {
        final Map<String, IdPAttribute> resolvedAttributes = resolveAttributes("user-2role-2attr.json", 
                "restdc-min.xml");
        Assert.assertEquals(resolvedAttributes.size(), 10);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
    }

    /**
     * Tests wheter dataconnector settings are valid.
     * @param dataConnector The data connector.
     * @param disregard Whether TLS should be disregarded or not.
     * @param prefix The attribute prefix.
     */
    protected void testSettings(final RestDataConnector dataConnector, final boolean disregard, final String prefix) {
        Assert.assertEquals(dataConnector.getId(), expectedId);
        Assert.assertEquals(dataConnector.getEndpointUrl(), expectedEndpointUrl);
        Assert.assertEquals(dataConnector.getToken(), expectedToken);        
        Assert.assertEquals(dataConnector.isDisregardTLSCertificate(), disregard);
        Assert.assertEquals(dataConnector.getResultAttributePrefix(), prefix);
        Assert.assertNotNull(dataConnector.getHttpClientBuilder());
    }
    
    /**
     * Resolves the attributes with the given settings.
     * @param userJson The User object response simulation from the REST endpoint.
     * @param connectorSettings The settings.
     * @return The map of resolved attributes.
     * @throws Exception
     */
    protected Map<String, IdPAttribute> resolveAttributes(String userJson, String connectorSettings) throws Exception {
        HttpClientBuilder mockBuilder = initializeMockBuilder(userJson);
        final RestDataConnector dataConnector = RestDataConnectorParserTest.initializeDataConnector(connectorSettings);
        final AttributeResolutionContext context = TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, 
                TestSources.IDP_ENTITY_ID, TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext =
        context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(expectedHookAttribute, "hookAttributeValue", workContext);
        recordWorkContextAttribute(expectedIdpId, "idpIdValue", workContext);
        RestDataConnector mockConnector = Mockito.spy(dataConnector);
        Mockito.doReturn(mockBuilder).when(mockConnector).getHttpClientBuilder();
        testSettings(dataConnector, false, "");
        return mockConnector.doResolve(context, workContext);
    }
    
    /**
     * Initializes a mocked {@link HttpClientBuilder}.
     * 
     * @param userJson The user object JSON declaration.
     * @return Mocked {@link HttpClientBuilder}.
     * @throws Exception
     */
    public HttpClientBuilder initializeMockBuilder(String userJson) throws Exception {
        HttpClientBuilder mockBuilder = Mockito.mock(HttpClientBuilder.class);
        CloseableHttpResponse mockResponse = Mockito.mock(CloseableHttpResponse.class);
        StatusLine mockStatusLine = Mockito.mock(StatusLine.class);
        Mockito.doReturn(200).when(mockStatusLine).getStatusCode();
        Mockito.when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        HttpEntity mockEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(mockResponse.getEntity()).thenReturn(mockEntity);
        Mockito.when(mockEntity.getContent()).thenReturn(getUserObjectStream(userJson));
        Mockito.when(mockClient.execute(Matchers.any(HttpUriRequest.class), Matchers.any(HttpContext.class)))
                .thenReturn(mockResponse);
        Mockito.when(mockBuilder.buildClient()).thenReturn(mockClient);
        return mockBuilder;
    }
    
    /**
     * Helper method to point JSON file declaration to correct directory and convert it to {@link InputStream}.
     * @param userJson The JSON filename, without directory prefix.
     * @return The stream corresponding to the file.
     * @throws Exception
     */
    protected InputStream getUserObjectStream(String userJson) throws Exception {
        return new FileInputStream("src/test/resources/fi/okm/mpass/shibboleth/attribute/resolver/data/" + userJson);
    }

    /**
     * Helper method for recording attribute name and value to {@link AttributeResolverWorkContext}.
     * 
     * @param attributeName The attribute name to be recorded.
     * @param attributeValue The attribute value to be recorded.
     * @param workContext The target {@link AttributeResolverWorkContext}.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute recording fails.
     */
    protected void recordWorkContextAttribute(final String attributeName, final String attributeValue,
            final AttributeResolverWorkContext workContext) throws ComponentInitializationException,
            ResolutionException {
        final AttributeDefinition definition = TestSources.populatedStaticAttribute(attributeName, attributeName, 1);
        workContext.recordAttributeDefinitionResolution(definition, populateAttribute(attributeName, attributeValue));
    }

    /**
     * Helper method for populating a String-valued attribute with given parameters.
     * 
     * @param attributeName The attribute name to be populated.
     * @param attributeValue The attribute value.
     * @return The populated {@link IdPAttribute}.
     */
    protected IdPAttribute populateAttribute(final String attributeName, final String attributeValue) {
        IdPAttribute idpAttribute = new IdPAttribute(attributeName);
        final List<IdPAttributeValue<String>> values = new ArrayList<>();
        values.add(new StringAttributeValue(attributeValue));
        idpAttribute.setValues(values);
        return idpAttribute;
    }
}
