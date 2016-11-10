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
package fi.okm.mpass.shibboleth.profile.audit.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link AttributeValueAuditExtractorTest}.
 */
public class AttributeValueAuditExtractorTest {

    /** Attribute id whose value is to be extracted. */
    protected String attributeId;
    
    /** Attribute value to be extracted. */
    protected String attributeValue;
    
    /** The request context containing the profile context. */
    protected RequestContext src;
    
    /** The profile context containing the relying party context. */
    protected ProfileRequestContext<?, ?> prc;
    
    /** The relying part context containing the attribute context. */
    protected RelyingPartyContext rp;
    
    /** The extractor to be tested. */
    protected AttributeValueAuditExtractor auditExtractor;
    
    /**
     * Configures the variables needed in testing.
     */
    @BeforeTest protected void setupTest() {
        attributeId = "mockAttributeId";
        attributeValue = "mockAttributeValue";
        auditExtractor = new AttributeValueAuditExtractor(attributeId);
    }
    
    /**
     * Populates the request context together with its relevant subcontexts.
     * 
     * @throws ComponentInitializationException If the contexts cannot be initialized.
     */
    @BeforeMethod public void populateContext() throws ComponentInitializationException {
        src = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(src);
        rp = prc.getSubcontext(RelyingPartyContext.class, true);
    }
    
    /**
     * Verifies that the construction fails with null function.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void initNullFunction() {
        auditExtractor = new AttributeValueAuditExtractor(null, attributeId);
    }
    
    /**
     * Verifies that the construction fails with null attributeId.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)    
    public void initNullAttributeId() {
        auditExtractor = new AttributeValueAuditExtractor(null);
    }
    
    /**
     * Test extractor without {@link AttributeContext}.
     */
    @Test public void testNoAttributeContext() {
        Collection<String> result = auditExtractor.apply(prc);
        Assert.assertEquals(result.size(), 0);
    }
    
    /**
     * Test extractor without any attributes in {@link AttributeContext}.
     */
    @Test public void testNoAttribute() {
        rp.getSubcontext(AttributeContext.class, true);
        Collection<String> result = auditExtractor.apply(prc);
        Assert.assertEquals(result.size(), 0);        
    }
    
    /**
     * Test extractor with single value for the configured attribute.
     */
    @Test public void testOne() {
        final AttributeContext attributeContext = rp.getSubcontext(AttributeContext.class, true);
        ArrayList<IdPAttribute> attributes = new ArrayList<>();
        IdPAttribute attribute = new IdPAttribute(attributeId);
        attribute.setValues(populateValue(attributeValue));
        attributes.add(attribute);
        attributeContext.setIdPAttributes(attributes);
        Collection<String> result = auditExtractor.apply(prc);
        Assert.assertEquals(result.size(), 1);
        Assert.assertEquals(result.iterator().next(), attributeValue);
    }
    
    /**
     * Test extractor with two values for the configured attribute.
     */
    @Test public void testTwo() {
        final AttributeContext attributeContext = rp.getSubcontext(AttributeContext.class, true);
        ArrayList<IdPAttribute> attributes = new ArrayList<>();
        IdPAttribute attribute = new IdPAttribute(attributeId);
        attribute.setValues(populateValue(attributeValue, "mockValue2"));
        attributes.add(attribute);
        attributeContext.setIdPAttributes(attributes);
        Collection<String> result = auditExtractor.apply(prc);
        Assert.assertEquals(result.size(), 2);
    }
    
    /**
     * Populates a collection of {@link StringAttributeValue}s.
     * @param values The input for the collection.
     * @return The collection of values.
     */
    protected Collection<StringAttributeValue> populateValue(String... values) {
        if (values == null || values.length == 0) {
            return Collections.emptyList();
        }
        ArrayList<StringAttributeValue> result = new ArrayList<>();
        for (int i = 0; i < values.length; i++) {
            result.add(new StringAttributeValue(values[i]));
        }
        return result;
    }
}
