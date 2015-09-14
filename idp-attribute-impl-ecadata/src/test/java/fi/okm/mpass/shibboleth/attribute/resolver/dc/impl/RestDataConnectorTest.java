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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

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

    /** The expected disregardTLSCertificate value. */
    private boolean expectedDisregardTLSCertificate;

    /** The expected resolved OID after successful resolution. */
    private String expectedOid;

    /**
     * Initialize unit tests.
     */
    @BeforeTest
    public void init() {
        expectedId = "restdc";
        expectedEndpointUrl = "testindEndpointUrl";
        expectedHookAttribute = "testingHookAttribute";
        expectedIdpId = "testingIdpId";
        expectedResultAttribute = "testingResultAttribute";
        expectedToken = "testingToken";
        expectedOid = "testUser";
    }

    /**
     * Tests {@link RestDataConnector} with minimum configuration.
     * 
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test
    public void testMinimum() throws ComponentInitializationException, ResolutionException, Exception {
        HttpClientBuilder mockBuilder = initializeMockBuilder(expectedOid);
        final RestDataConnector dataConnector = RestDataConnectorParserTest.initializeDataConnector("restdc-min.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext =
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(expectedHookAttribute, "hookAttributeValue", workContext);
        recordWorkContextAttribute(expectedIdpId, "idpIdValue", workContext);
        RestDataConnector mockConnector = Mockito.spy(dataConnector);
        Mockito.doReturn(mockBuilder).when(mockConnector).getHttpClientBuilder();
        final Map<String, IdPAttribute> resolvedAttributes = mockConnector.doResolve(context, workContext);
        Assert.assertEquals(dataConnector.getId(), expectedId);
        Assert.assertEquals(dataConnector.getEndpointUrl(), expectedEndpointUrl);
        Assert.assertEquals(dataConnector.getToken(), expectedToken);
        Assert.assertEquals(dataConnector.isDisregardTLSCertificate(), expectedDisregardTLSCertificate);
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(expectedResultAttribute).getValues().get(0).getValue(), expectedOid);
    }

    /**
     * Tests full resolution.
     * 
     * @throws Exception
     */
    @Test
    public void test() throws Exception {
        HttpClientBuilder mockBuilder = initializeMockBuilder(expectedOid);
        RestDataConnector dataConnector = new RestDataConnector();
        dataConnector.setId("testingId");
        dataConnector.setEndpointUrl("testingEndpoint");
        dataConnector.setHookAttribute("testingAttribute");
        dataConnector.setIdpId("testingIdpId");
        dataConnector.setResultAttribute("testingResultAttribute");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext =
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        RestDataConnector mockConnector = Mockito.spy(dataConnector);

        Mockito.doReturn(mockBuilder).when(mockConnector).getHttpClientBuilder();

        Map<String, IdPAttribute> attributes = mockConnector.doResolve(context, workContext);
        Assert.assertEquals(attributes.size(), 1);
        Assert.assertNotNull(attributes.get("testingResultAttribute"));
        Assert.assertEquals(attributes.get("testingResultAttribute").getValues().size(), 1);
        Assert.assertEquals(attributes.get("testingResultAttribute").getValues().get(0).getValue(), "testUser");
    }

    /**
     * Initializes a mocked {@link HttpClientBuilder}.
     * 
     * @param expectedUsername The username value in the simulated JSON response stream.
     * @return Mocked {@link HttpClientBuilder}.
     * @throws Exception
     */
    public HttpClientBuilder initializeMockBuilder(String expectedUsername) throws Exception {
        HttpClientBuilder mockBuilder = Mockito.mock(HttpClientBuilder.class);
        CloseableHttpResponse mockResponse = Mockito.mock(CloseableHttpResponse.class);
        StatusLine mockStatusLine = Mockito.mock(StatusLine.class);
        Mockito.doReturn(200).when(mockStatusLine).getStatusCode();
        Mockito.when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        HttpClient mockClient = Mockito.mock(HttpClient.class);
        HttpEntity mockEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(mockResponse.getEntity()).thenReturn(mockEntity);
        ByteArrayInputStream inputStream =
                new ByteArrayInputStream(
                        ("{ \"username\":\"" + expectedUsername + "\" }").getBytes(StandardCharsets.UTF_8));
        Mockito.when(mockEntity.getContent()).thenReturn(inputStream);
        Mockito.when(mockClient.execute(Matchers.any(HttpUriRequest.class), Matchers.any(HttpContext.class)))
                .thenReturn(mockResponse);
        Mockito.when(mockBuilder.buildClient()).thenReturn(mockClient);
        return mockBuilder;
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
