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
package fi.okm.mpass.shibboleth.profile.metadata.spring;

import javax.xml.namespace.QName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.beans.factory.parsing.Location;
import org.springframework.beans.factory.parsing.Problem;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import fi.okm.mpass.shibboleth.profile.metadata.DataSourceMetadataResolver;
import net.shibboleth.idp.profile.spring.relyingparty.metadata.impl.AbstractReloadingMetadataProviderParser;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * The bean definition parser for <code>urn:mpassid:shib3:metadata</code>.
 */
public class DataSourceMetadataProviderParser extends AbstractReloadingMetadataProviderParser {

    /** The namespace for the metadata parser. */
    public static final String MPASS_METADATA_NAMESPACE = "urn:mpassid:shib3:metadata";
    
    /** Element name. */
    public static final QName ELEMENT_NAME =
            new QName(MPASS_METADATA_NAMESPACE, "DataSourceMetadataProvider");

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(DataSourceMetadataProviderParser.class);
    
    /** {@inheritDoc} */
    @Override protected Class<DataSourceMetadataResolver> getNativeBeanClass(Element element) {
        return DataSourceMetadataResolver.class;
    }

    /** {@inheritDoc} */
    @Override protected void doNativeParse(Element element, ParserContext parserContext,
            BeanDefinitionBuilder builder) {

        super.doNativeParse(element, parserContext, builder);

        if (element.hasAttributeNS(null, "dataSource")) {
            builder.addConstructorArgReference(StringSupport.trimOrNull(element.getAttributeNS(null, "dataSource")));
        } else {
            log.error("{}: dataSource configuration not found", parserContext.getReaderContext().getResource()
                    .getDescription());
            throw new BeanDefinitionParsingException(new Problem("dataSource configuration not found",
                    new Location(parserContext.getReaderContext().getResource())));
        }
    }
}
