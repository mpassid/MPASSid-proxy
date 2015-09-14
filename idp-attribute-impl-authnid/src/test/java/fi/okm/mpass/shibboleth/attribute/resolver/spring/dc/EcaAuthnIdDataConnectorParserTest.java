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

import java.util.ArrayList;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.okm.mpass.shibboleth.attribute.resolver.dc.impl.EcaAuthnIdDataConnector;
import net.shibboleth.idp.attribute.resolver.spring.BaseAttributeDefinitionParserTest;

/**
 * Unit tests for {@link EcaAuthnIdDataConnectorParser}.
 */
public class EcaAuthnIdDataConnectorParserTest extends BaseAttributeDefinitionParserTest {
    
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
     * Tests parsing of the {@link EcaAuthnIdDataConnector} from XML configuration.
     */
    @Test public void testParsing() {
        final EcaAuthnIdDataConnector dataConnector = initializeDataConnector("authnid-min.xml");
        Assert.assertEquals(dataConnector.getId(), "authnid");
        Assert.assertNull(dataConnector.getFailoverDataConnectorId());
        Assert.assertNotNull(dataConnector.getSrcAttributeNames());
        Assert.assertEquals(dataConnector.getSrcAttributeNames().size(), 1);
        Assert.assertEquals(dataConnector.getSrcAttributeNames().get(0), srcAttributeName);
        Assert.assertEquals(dataConnector.getDestAttributeName(), destAttributeName);
    }

    /**
     * Constructs and initializes an instance of {@link EcaAuthnIdDataConnector} as configured in
     * the given file.
     * 
     * @param configFile The configuration file for the data connector.
     * @return Returns the configured data connector.
     */
    public static EcaAuthnIdDataConnector initializeDataConnector(final String configFile) {
        EcaAuthnIdDataConnectorParserTest instance = new EcaAuthnIdDataConnectorParserTest();
        return instance.getDataConnector(configFile, EcaAuthnIdDataConnector.class);
    }
}
