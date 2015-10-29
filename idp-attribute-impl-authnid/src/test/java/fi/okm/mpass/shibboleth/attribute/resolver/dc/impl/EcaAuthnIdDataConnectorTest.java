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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.okm.mpass.shibboleth.attribute.resolver.spring.dc.EcaAuthnIdDataConnectorParserTest;

/**
 * Unit tests for {@link EcaAuthnIdDataConnector}.
 */
public class EcaAuthnIdDataConnectorTest {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EcaAuthnIdDataConnectorTest.class);
    
    /** The single srcAttributeName used in testing. */
    private String srcAttributeName;

    /** Multiple srcAttributeNames used in testing. */
    private List<String> srcAttributeNames;
    
    /** Values for srcAttributeNames used in testing. */
    private List<String> srcAttributeValues;
    
    /** The destAttributeName used in testing. */
    private String destAttributeName;
    
    /**
     * Initializes the class variables.
     */
    @BeforeTest protected void initTests() {
        srcAttributeName = "testingSrc";
        srcAttributeNames = new ArrayList<String>();
        srcAttributeNames.add("testingSrc1");
        srcAttributeNames.add("testingSrc2");
        srcAttributeNames.add("testingSrc3");
        srcAttributeValues = new ArrayList<String>();
        srcAttributeValues.add("testingInputSource");
        srcAttributeValues.add("testingInputSource2");
        srcAttributeValues.add("testingInputSource3");
        destAttributeName = "testingDest";
    }
    
    /**
     * Tests {@link EcaAuthnIdDataConnector} with minimum configuration.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test public void testMinimum() throws ComponentInitializationException, ResolutionException {
        final EcaAuthnIdDataConnector dataConnector = 
                EcaAuthnIdDataConnectorParserTest.initializeDataConnector("authnid-min.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext = 
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(srcAttributeName, srcAttributeValues.get(0), workContext); 
        final Map<String, IdPAttribute> resolvedAttributes = dataConnector.resolve(context);
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(destAttributeName).getValues().get(0).getValue(), 
                "9MRUli6t2hQIhLKlVK/n2IAwVzZpCreaZ6dAyE7CHL8=");
    }
    
    /**
     * Tests {@link EcaAuthnIdDataConnector} with configuration for three source attributes.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test public void testThreeSources() throws ComponentInitializationException, ResolutionException {
        final EcaAuthnIdDataConnector dataConnector = 
                EcaAuthnIdDataConnectorParserTest.initializeDataConnector("authnid-3sources.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext = 
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        for (int i = 0; i < srcAttributeNames.size(); i++) {
            recordWorkContextAttribute(srcAttributeNames.get(i), srcAttributeValues.get(i), workContext);
        }
        final Map<String, IdPAttribute> resolvedAttributes = dataConnector.resolve(context);
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(destAttributeName).getValues().get(0).getValue(), 
                "w/AW7WOwjcS/8ibBkbD91eVhb7Kh73tRZhHS+u6AVkM=");
        
    }
    
    /**
     * Tests {@link EcaAuthnIdDataConnector} with minimum salted configuration.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test public void testMinimumSalted() throws ComponentInitializationException, ResolutionException {
        final EcaAuthnIdDataConnector dataConnector = 
                EcaAuthnIdDataConnectorParserTest.initializeDataConnector("authnid-salted.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext = 
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(srcAttributeName, srcAttributeValues.get(0), workContext); 
        final Map<String, IdPAttribute> resolvedAttributes = dataConnector.resolve(context);
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(destAttributeName).getValues().get(0).getValue(), 
                "/koIA2Xy/utNm9/f6c4HPnGb2bZ/0nRKOTd2BAQfFL8=");
    }
    
    /**
     * Tests {@link EcaAuthnIdDataConnector} with configuration using all parameters.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test public void testFull() throws ComponentInitializationException, ResolutionException {
        final EcaAuthnIdDataConnector dataConnector = 
                EcaAuthnIdDataConnectorParserTest.initializeDataConnector("authnid-full.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext = 
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(srcAttributeName, srcAttributeValues.get(0), workContext);
        recordWorkContextAttribute("testingSkipping", "skipValue1", workContext);
        final Map<String, IdPAttribute> resolvedAttributes = dataConnector.resolve(context);
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(destAttributeName).getValues().get(0).getValue(), 
                srcAttributeValues.get(0));
        
    }
    
    /**
     * Tests {@link EcaAuthnIdDataConnector} with configuration that skips calculation.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test public void testSkip() throws ComponentInitializationException, ResolutionException {
        final EcaAuthnIdDataConnector dataConnector = 
                EcaAuthnIdDataConnectorParserTest.initializeDataConnector("authnid-skip.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext = 
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(srcAttributeName, srcAttributeValues.get(0), workContext);
        recordWorkContextAttribute("idpId", "skipId", workContext);
        final Map<String, IdPAttribute> resolvedAttributes = dataConnector.resolve(context);
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(destAttributeName).getValues().get(0).getValue(), 
                srcAttributeValues.get(0));
    }
    
    /**
     * Tests {@link EcaAuthnIdDataConnector} with configuration that skips calculation.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute resolution fails.
     */
    @Test public void testSkip2() throws ComponentInitializationException, ResolutionException {
        final EcaAuthnIdDataConnector dataConnector = 
                EcaAuthnIdDataConnectorParserTest.initializeDataConnector("authnid-skip.xml");
        final AttributeResolutionContext context =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final AttributeResolverWorkContext workContext = 
                context.getSubcontext(AttributeResolverWorkContext.class, false);
        recordWorkContextAttribute(srcAttributeName, srcAttributeValues.get(0), workContext);
        recordWorkContextAttribute("idpId", "skipId2", workContext);
        final Map<String, IdPAttribute> resolvedAttributes = dataConnector.resolve(context);
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertEquals(resolvedAttributes.size(), 1);
        Assert.assertEquals(resolvedAttributes.get(destAttributeName).getValues().get(0).getValue(), 
                srcAttributeValues.get(0));
    }
    
    /**
     * Helper method for recording attribute name and value to {@link AttributeResolverWorkContext}.
     * @param attributeName The attribute name to be recorded.
     * @param attributeValue The attribute value to be recorded.
     * @param workContext The target {@link AttributeResolverWorkContext}.
     * @throws ComponentInitializationException If component cannot be initialized.
     * @throws ResolutionException If attribute recording fails.
     */
    protected void recordWorkContextAttribute(final String attributeName, final String attributeValue, 
            final AttributeResolverWorkContext workContext) 
                    throws ComponentInitializationException, ResolutionException {
        final AttributeDefinition definition = 
                TestSources.populatedStaticAttribute(attributeName, attributeName, 1);
        workContext.recordAttributeDefinitionResolution(definition, 
                populateAttribute(attributeName, attributeValue));       
    }
    
    /**
     * Helper method for populating a String-valued attribute with given parameters.
     * @param attributeName The attribute name to be populated.
     * @param attributeValue The attribute value.
     * @return The populated {@link IdPAttribute}.
     */
    protected IdPAttribute populateAttribute(final String attributeName, final String attributeValue) {
        log.debug("Populating an IdPAttribute with name {} = {}", attributeName, attributeValue);
        IdPAttribute idpAttribute = new IdPAttribute(attributeName);
        final List<IdPAttributeValue<String>> values = new ArrayList<>();
        values.add(new StringAttributeValue(attributeValue));
        idpAttribute.setValues(values);
        return idpAttribute;
    }
}
