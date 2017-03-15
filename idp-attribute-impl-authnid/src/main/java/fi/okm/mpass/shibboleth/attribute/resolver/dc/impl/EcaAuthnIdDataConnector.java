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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AbstractDataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.ResolvedAttributeDefinition;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class implements a {@link DataConnector} (resolver plugin) that calculates the ECA authn ID with the configured
 * parameters.
 * 
 * Example configuration (in attribute-resolver.xml):
 * 
 * <resolver:DataConnector id="calculateAuthnId" xsi:type="ecaid:AuthnIdDataConnector" srcAttributeNames="uid"
 * destAttributeName="authnid"/>
 */
public class EcaAuthnIdDataConnector extends AbstractDataConnector {

    /** Default minimum input length if it's not set. */
    public static final int DEFAULT_MINIMUM_INPUT_LENGTH = 10;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(EcaAuthnIdDataConnector.class);

    /** The list of source attribute ids. */
    private List<String> srcAttributeNames;

    /** The attribute id where to put the value of calculated authnID. */
    private String destAttributeName;

    /** The pre-salt to be used together with source attributes before calculating authnID. */
    private String prefixSalt;

    /** The post-salt to be used together with source attributes before calculating authnID. */
    private String postfixSalt;

    /** The minimum length of source attribute values (without salt). */
    private int minInputLength;

    /** The attribute id vs value map for skipping the authnID calculation. */
    private Map<String, List<String>> skipCalculation;

    /** The attribute id to be used if calculation has been skipped. */
    private String skipCalculationSrc;

    @Nullable
    @Override
    /** {@inheritDoc} */
    protected Map<String, IdPAttribute> doDataConnectorResolve(
            @Nonnull final AttributeResolutionContext attributeResolutionContext,
            @Nonnull final AttributeResolverWorkContext attributeResolverWorkContext) throws ResolutionException {

        final String uid = attributeResolutionContext.getPrincipal();
        log.debug("Calculating authnID for {}", uid);

        final Map<String, ResolvedAttributeDefinition> attributeDefinitions =
                attributeResolverWorkContext.getResolvedIdPAttributeDefinitions();
        if (log.isTraceEnabled()) {
            log.trace("Listing attribute definitions ({}) from the work context", attributeDefinitions.size());
            final Iterator<String> iterator = attributeDefinitions.keySet().iterator();
            while (iterator.hasNext()) {
                final String key = iterator.next();
                log.trace("Attribute key {}, value {}", key, attributeDefinitions.get(key).getResolvedAttribute());
            }
        }

        if (skipCalculation.size() > 0) {
            log.debug("Checking whether request meets skipCalculation configuration");
            final Iterator<String> iterator = getSkipCalculation().keySet().iterator();
            while (iterator.hasNext()) {
                final String key = iterator.next();
                log.trace("Inspecting skipCalculation setting {}", key);
                if (attributeDefinitions.get(key) != null) {
                    log.trace("Attribute {} found from the context", key);
                    if (sourceExistsInAnother(getSkipCalculation().get(key), attributeDefinitions.get(key)
                            .getResolvedAttribute().getValues())) {
                        log.debug("skipCalculation configuration matched");
                        // First source attribute is used
                        return buildResponse(collectSingleAttributeValue(attributeDefinitions, 
                                srcAttributeNames.get(0)));
                    }
                } else {
                    log.trace("Attribute {} was not found in the context", key);
                }
            }
        } else {
            log.debug("No skipCalculation attribute defined");
        }

        final String preSaltInput = collectAuthnIdInput(attributeDefinitions);
        if (preSaltInput.length() < minInputLength) {
            log.error("The input for the authn ID calculation is too simple (length = {}), cannot continue",
                    preSaltInput.length());
            return new HashMap<String, IdPAttribute>();
        }

        final String authnIdInput = saltAuthnIdInput(preSaltInput);

        final String authnId = calculateAuthnId(authnIdInput);
        if (authnId != null) {
            log.info("Authn ID successfully calculated and included in the attribute {}", destAttributeName);
            return buildResponse(authnId);
        } else {
            log.error("Authn ID calculation failed.");
            return new HashMap<String, IdPAttribute>();
        }
    }

    /**
     * Builds a response map with the given contents. The attribute id will be taken from the global destAttributeName
     * variable.
     * 
     * @param value The value for destAttributeName.
     * @return The response in a Map.
     */
    protected Map<String, IdPAttribute> buildResponse(final String value) {
        final Map<String, IdPAttribute> attributes = new HashMap<>();
        final IdPAttribute idpAttribute = new IdPAttribute(getDestAttributeName());
        final List<IdPAttributeValue<String>> values = new ArrayList<>();
        values.add(new StringAttributeValue(value));
        idpAttribute.setValues(values);
        attributes.put(getDestAttributeName(), idpAttribute);
        return attributes;
    }

    /**
     * Helper method for checking whether any values in the source list exist in the target list (using
     * getDisplayValue).
     * 
     * @param source The source list.
     * @param targetValues The target list.
     * @return True if exists, false otherwise.
     */
    protected boolean sourceExistsInAnother(final List<String> source, final List<IdPAttributeValue<?>> targetValues) {
        for (int i = 0; i < source.size(); i++) {
            for (int j = 0; j < targetValues.size(); j++) {
                log.trace("Comparing {} to {}", source.get(i), targetValues.get(j).getDisplayValue());
                final Object targetValue = targetValues.get(j).getValue();
                if (targetValue instanceof String && source.get(i).equals((String) targetValue)) {
                    log.debug("Strings are corresponding, returning true");
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Collects the attribute values corresponding to the source attribute configuration. The attribute values are
     * concatenated to the resulting string in the same order as they are included in the source array. If any value is
     * not found, it'll be warned in the logs. Only single value attributes are accepted.
     * 
     * @param attributeDefinitions the resolved attribute definitions.
     * @return The concatenated attribute values.
     */
    protected String collectAuthnIdInput(@Nonnull final Map<String, ResolvedAttributeDefinition> attributeDefinitions) {
        String authnIdInput = "";
        for (int i = 0; i < srcAttributeNames.size(); i++) {
            final String srcAttributeName = srcAttributeNames.get(i);
            authnIdInput = authnIdInput.concat(collectSingleAttributeValue(attributeDefinitions, srcAttributeName));
        }
        return authnIdInput;
    }

    /**
     * Collects a single {@link String} value from the list of {@link IdPAttributeValue}s.
     * 
     * @param values The list of values.
     * @return The value if single was found, null otherwise.
     */
    protected String collectSingleAttributeValue(@Nonnull final List<IdPAttributeValue<?>> values) {
        if (values.size() == 0 || values.size() > 1) {
            log.debug("No single value found for the attribute, the set size was {}", values.size());
            return null;
        }
        return (String) values.get(0).getValue();
    }

    /**
     * Collects a single {@link String} value from the map of attributes with given parameters.
     * 
     * @param attributeDefinitions The map of attributes.
     * @param attributeName The attribute id whose value is to be collected.
     * @return The value if single was found, null otherwise.
     */
    protected String collectSingleAttributeValue(
            @Nonnull final Map<String, ResolvedAttributeDefinition> attributeDefinitions,
            @Nonnull final String attributeName) {
        final ResolvedAttributeDefinition definition = attributeDefinitions.get(attributeName);
        if (definition == null || definition.getResolvedAttribute() == null) {
            log.warn("Could not find an attribute {} from the context", attributeName);
            return null;
        } else {
            return collectSingleAttributeValue(definition.getResolvedAttribute().getValues());
        }
    }

    /**
     * Adds the prefix- and postfix-salts to the given string.
     * 
     * @param preSaltInput the input to be salted.
     * @return The salted result.
     */
    protected String saltAuthnIdInput(@NotEmpty final String preSaltInput) {
        return prefixSalt + preSaltInput + postfixSalt;
    }

    /**
     * Calculates the authn ID with the given input. SHA-256 is used as a digest algorithm and UTF-8 as character
     * encoding.
     * 
     * @param input The input for the calculation.
     * @return The calculated authn ID.
     */
    protected String calculateAuthnId(@Nonnull @NotEmpty final String input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(input.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            log.error("Could not use the configured digest algorithm", e);
            return null;
        } catch (UnsupportedEncodingException e) {
            log.error("Could not encode the input for the digest algorithm", e);
            return null;
        }
        byte[] digest = md.digest();
        return new String(Base64.encode(digest));
    }

    /**
     * Set the list of source attribute ids.
     * 
     * @param attributeNames What to set in comma-separated list.
     */
    public void setSrcAttributeNames(@Nonnull final String attributeNames) {
        log.debug("Converting string {} to the array", attributeNames);
        srcAttributeNames =
                StringSupport.stringToList(
                        Constraint.isNotEmpty(attributeNames, "The srcAttributeNames configuration cannot be empty!"),
                        ",");
    }

    /**
     * Get the list of source attribute ids.
     * 
     * @return The srcAttributeNames.
     */
    public List<String> getSrcAttributeNames() {
        return this.srcAttributeNames;
    }

    /**
     * Set the attribute id where to put the value of calculated authnID.
     * 
     * @param attributeName What to set.
     */
    public void setDestAttributeName(@Nonnull final String attributeName) {
        this.destAttributeName =
                Constraint.isNotEmpty(attributeName, "The destAttributeName configuration may not be empty!");
    }

    /**
     * Get the attribute id where to put the value of calculated authnID.
     * 
     * @return The destAtributeName.
     */
    public String getDestAttributeName() {
        return this.destAttributeName;
    }

    /**
     * Set the pre-salt to be used together with source attributes before calculating authnID.
     * 
     * @param preSalt What to set.
     */
    public void setPrefixSalt(final String preSalt) {
        if (preSalt == null) {
            this.prefixSalt = "";
        } else {
            this.prefixSalt = preSalt;
        }
    }

    /**
     * Get the pre-salt to be used together with source attributes before calculating authnID.
     * 
     * @return The prefixSalt.
     */
    public String getPrefixSalt() {
        return this.prefixSalt;
    }

    /**
     * Set the post-salt to be used together with source attributes before calculating authnID.
     * 
     * @param postSalt What to set.
     */
    public void setPostfixSalt(final String postSalt) {
        if (postSalt == null) {
            this.postfixSalt = "";
        } else {
            this.postfixSalt = postSalt;
        }
    }

    /**
     * Get the post-salt to be used together with source attributes before calculating authnID.
     * 
     * @return The postfixSalt.
     */
    public String getPostfixSalt() {
        return this.postfixSalt;
    }

    /**
     * Set the minimum length of source attribute values (without salt).
     * 
     * @param minLength What to set (numeric).
     */
    public void setMinInputLength(final String minLength) {
        if (minLength == null) {
            minInputLength = DEFAULT_MINIMUM_INPUT_LENGTH;
        } else {
            minInputLength = Integer.parseInt(minLength);
        }
    }

    /**
     * Get the minimum length of source attribute values (without salt).
     * 
     * @return The minInputLength.
     */
    public int getMinInputLength() {
        return this.minInputLength;
    }

    /**
     * Get the attribute id vs value map for skipping the authnID calculation.
     * 
     * @return the skipCalculation.
     */
    public Map<String, List<String>> getSkipCalculation() {
        return skipCalculation;
    }

    /**
     * Set the attribute id vs value map for skipping the authnID calculation.
     * 
     * @param skipCalc What to set.
     */
    public void setSkipCalculation(String skipCalc) {
        skipCalculation = new HashMap<String, List<String>>();
        if (StringSupport.trimOrNull(skipCalc) == null) {
            return;
        }
        final StringTokenizer tokenizer = new StringTokenizer(skipCalc, ",");
        while (tokenizer.hasMoreTokens()) {
            final String pair = tokenizer.nextToken();
            log.debug("Parsing the skipCalculation token {}", pair);
            final StringTokenizer pairTokenizer = new StringTokenizer(pair, "=");
            if (pairTokenizer.countTokens() < 2) {
                log.warn("Could not parse skipCalculation token {}", pair);
            } else {
                final String attributeName = pairTokenizer.nextToken();
                String attributeValue = "";
                while (pairTokenizer.hasMoreTokens()) {
                    attributeValue = attributeValue.concat(pairTokenizer.nextToken());
                }
                if (skipCalculation.get(attributeName) != null) {
                    log.debug("Adding the value {} to the existing entry {}", attributeValue, attributeName);
                    skipCalculation.get(attributeName).add(attributeValue);
                } else {
                    log.debug("Creating a new entry {} with value {}", attributeName, attributeValue);
                    final List<String> newValue = new ArrayList<String>();
                    newValue.add(attributeValue);
                    skipCalculation.put(attributeName, newValue);
                }
            }
        }
    }

    /**
     * Get the attribute id to be used if calculation has been skipped.
     * 
     * @return The skipCalculationSrc.
     */
    public String getSkipCalculationSrc() {
        return skipCalculationSrc;
    }

    /**
     * Set the attribute id to be used if calculation has been skipped.
     * 
     * @param skipCalcSrc What to set.
     */
    public void setSkipCalculationSrc(String skipCalcSrc) {
        this.skipCalculationSrc = skipCalcSrc;
    }
}