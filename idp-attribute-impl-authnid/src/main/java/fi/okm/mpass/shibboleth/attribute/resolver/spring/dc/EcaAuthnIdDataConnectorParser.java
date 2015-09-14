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

import javax.xml.namespace.QName;

import net.shibboleth.idp.attribute.resolver.spring.dc.AbstractDataConnectorParser;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import fi.okm.mpass.shibboleth.attribute.resolver.dc.impl.EcaAuthnIdDataConnector;

/**
 * Spring bean definition parser for configuring {@link EcaAuthnIdDataConnector}.
 */
public class EcaAuthnIdDataConnectorParser extends AbstractDataConnectorParser {
//public class EcaAuthnIdDataConnectorParser extends BaseResolverPluginParser { 
    
    /** Schema type. */
    public static final QName SCHEMA_NAME = new QName(EcaAuthnIdDataConnectorNamespaceHandler.NAMESPACE,
            "AuthnIdDataConnector");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EcaAuthnIdDataConnectorParser.class);
    
    /** {@inheritDoc} */
    protected Class<EcaAuthnIdDataConnector> getNativeBeanClass() {
        return EcaAuthnIdDataConnector.class;
    }

    /** {@inheritDoc} */
    protected void doV2Parse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        log.debug("Parsing the element");
        String srcAttributeNames = element.getAttributeNS(null, "srcAttributeNames");
        log.debug("Using srcAttributeNames={}", srcAttributeNames);
        builder.addPropertyValue("srcAttributeNames", srcAttributeNames);
        String destAttributeName = element.getAttributeNS(null, "destAttributeName");
        log.debug("Using destAttributeName={}", destAttributeName);
        builder.addPropertyValue("destAttributeName", destAttributeName);
        String prefixSalt = StringSupport.trimOrNull(element.getAttributeNS(null, "prefixSalt"));
        log.debug("Using prefixSalt={}", prefixSalt);
        builder.addPropertyValue("prefixSalt", prefixSalt);
        String postfixSalt = StringSupport.trimOrNull(element.getAttributeNS(null, "postfixSalt"));
        log.debug("Using postfixSalt={}", postfixSalt);
        builder.addPropertyValue("postfixSalt", postfixSalt);
        String minInputLength = StringSupport.trimOrNull(element.getAttributeNS(null, "minInputLength"));
        log.debug("Using minInputLength={}", minInputLength);
        builder.addPropertyValue("minInputLength", minInputLength);
        String skipCalculation = StringSupport.trimOrNull(element.getAttributeNS(null, "skipCalculation"));
        log.debug("Using skipCalculation={}", skipCalculation);
        builder.addPropertyValue("skipCalculation", skipCalculation);
        String skipCalculationSrc = StringSupport.trimOrNull(element.getAttributeNS(null, "skipCalculationSrc"));
        log.debug("Using skipCalculationSrc={}", skipCalculationSrc);
        builder.addPropertyValue("skipCalculationSrc", skipCalculationSrc);
    }
}
