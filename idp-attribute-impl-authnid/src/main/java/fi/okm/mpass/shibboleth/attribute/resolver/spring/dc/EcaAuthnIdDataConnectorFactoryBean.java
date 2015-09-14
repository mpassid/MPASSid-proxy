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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.shibboleth.attribute.resolver.dc.impl.EcaAuthnIdDataConnector;
import net.shibboleth.ext.spring.factory.AbstractComponentAwareFactoryBean;

/**
 * A Factory bean to summon up {@link EcaAuthnIdDataConnector} from supplied attributes.
 */
public class EcaAuthnIdDataConnectorFactoryBean extends AbstractComponentAwareFactoryBean<EcaAuthnIdDataConnector> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EcaAuthnIdDataConnectorFactoryBean.class);
    
    /** Comma-separated list of source attribute ids. */
    private String srcAttributeNames;

    /** The attribute id where to put the value of calculated authnID. */
    private String destAttributeName;

    /** The pre-salt to be used together with source attributes before calculating authnID. */
    private String prefixSalt;

    /** The post-salt to be used together with source attributes before calculating authnID. */
    private String postfixSalt;

    /** The minimum length of source attribute values (without salt). */
    private String minInputLength;
    
    /** The comma-separated list of attribute_name and attribute_value pairs for skipping calculation. */
    private String skipCalculation;
    
    /** The attribute id to be used if calculation has been skipped. */
    private String skipCalculationSrc;

    @Override
    /** {@inheritDoc} */
    public Class<EcaAuthnIdDataConnector> getObjectType() {
        log.debug("Returning the objec type");
        return EcaAuthnIdDataConnector.class;
    }

    @Override
    /** {@inheritDoc} */
    protected EcaAuthnIdDataConnector doCreateInstance() throws Exception {
        log.debug("Creating a new instance");
        final EcaAuthnIdDataConnector dataConnector = new EcaAuthnIdDataConnector();
        dataConnector.setSrcAttributeNames(getSrcAttributeNames());
        dataConnector.setDestAttributeName(getDestAttributeName());
        dataConnector.setPrefixSalt(getPrefixSalt());
        dataConnector.setPostfixSalt(getPostfixSalt());
        dataConnector.setMinInputLength(getMinInputLength());
        dataConnector.setSkipCalculation(getSkipCalculation());
        dataConnector.setSkipCalculationSrc(getSkipCalculationSrc());
        return dataConnector;
    }

    /**
     * Get the comma-separated list of source attribute ids.
     * 
     * @return Returns the srcAttributeNames.
     */
    public String getSrcAttributeNames() {
        return srcAttributeNames;
    }

    /**
     * Set the comma-separated list of source attribute ids.
     * 
     * @param attributeNames What to set.
     */
    public void setSrcAttributeNames(final String attributeNames) {
        this.srcAttributeNames = attributeNames;
    }

    /**
     * Get the attribute id where to put the value of calculated authnID.
     * 
     * @return Returns the destAttributeName.
     */
    public String getDestAttributeName() {
        return destAttributeName;
    }

    /**
     * Set the attribute id where to put the value of calculated authnID.
     * 
     * @param attributeName What to set.
     */
    public void setDestAttributeName(final String attributeName) {
        this.destAttributeName = attributeName;
    }

    
    /**
     * Get the pre-salt to be used together with source attributes before calculating authnID.
     * 
     * @return Returns the prefixSalt.
     */
    public String getPrefixSalt() {
        return prefixSalt;
    }

    /**
     * Set the pre-salt to be used together with source attributes before calculating authnID.
     * 
     * @param preSalt What to set.
     */
    public void setPrefixSalt(final String preSalt) {
        this.prefixSalt = preSalt;
    }

    /**
     * Get the post-salt to be used together with source attributes before calculating authnID.
     * 
     * @return Returns the postfixSalt.
     */
    public String getPostfixSalt() {
        return postfixSalt;
    }

    /**
     * Set the post-salt to be used together with source attributes before calculating authnID.
     * 
     * @param postSalt What to set.
     */
    public void setPostfixSalt(final String postSalt) {
        this.postfixSalt = postSalt;
    }

    /**
     * Get the minimum length of source attribute values (without salt).
     * 
     * @return Returns the minInputLength.
     */
    public String getMinInputLength() {
        return minInputLength;
    }

    /**
     * Set the minimum length of source attribute values (without salt).
     * 
     * @param minLength What to set (numeric).
     */
    public void setMinInputLength(final String minLength) {
        this.minInputLength = minLength;
    }
    
    /**
     * Get the comma-separated list of attribute_name and attribute_value pairs for skipping calculation.
     * 
     * @return Returns the skipCalculation.
     */
    public String getSkipCalculation() {
        return this.skipCalculation;
    }
    
    /**
     * Set the comma-separated list of attribute_name and attribute_value pairs for skipping calculation.
     * 
     * @param skipCalc What to set.
     */
    public void setSkipCalculation(final String skipCalc) {
        this.skipCalculation = skipCalc;
    }
    
    /**
     * Get the attribute id to be used if calculation has been skipped.
     * 
     * @return Returns the skipCalculationSrc.
     */
    public String getSkipCalculationSrc() {
        return this.skipCalculationSrc;
    }
    
    /**
     * Set the attribute id to be used if calculation has been skipped.
     * 
     * @param skipCalcSrc What to set.
     */
    public void setSkipCalculationSrc(final String skipCalcSrc) {
        this.skipCalculationSrc = skipCalcSrc;
    }
    
}