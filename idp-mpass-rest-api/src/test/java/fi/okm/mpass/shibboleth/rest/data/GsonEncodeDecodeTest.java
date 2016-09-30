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

package fi.okm.mpass.shibboleth.rest.data;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.gson.Gson;

/**
 * Unit tests for the data transfer objects.
 */
public class GsonEncodeDecodeTest {
    
    /** The id for {@link MetaDTO}. */
    private String id;

    /** The SAML entity ID for {@link MetaDTO}. */
    private String samlEntityId;

    /** The SAML metadata URL for {@link MetaDTO}. */
    private String samlMetadataUrl;

    /** The name for {@link MetaDTO}. */
    private String name;

    /** The organization for {@link MetaDTO}. */
    private String organization;

    /** The country code for {@link MetaDTO}. */
    private String countryCode;

    /** The service description for {@link MetaDTO}. */
    private String serviceDescription;

    /** The contact email for {@link MetaDTO}. */
    private String contactEmail;
    
    /** The code for {@link ErrorDTO}. */
    private int code;
    
    /** The message for {@link ErrorDTO}. */
    private String message;
    
    /** The fields for {@link ErrorDTO}. */
    private String fields;

    /** The JSON encoder/decoder. */
    private final Gson gson = new Gson();
    
    /**
     * Initialize variables.
     */
    @BeforeMethod
    public void initTests() {
        id = "mockId";
        samlEntityId = "mockSamlEntityId";
        samlMetadataUrl = "mockSamlMetadataUrl";
        name = "mockName";
        organization = "mockOrganization";
        countryCode = "fi";
        serviceDescription = "mockDescription";
        contactEmail = "mockEmail";
        code = 200;
        message = "mockMessage";
        fields = "mockFields";
    }
    
    /**
     * Test {@link MetaDTO} encoding and decoding.
     * @throws Exception
     */
    @Test
    public void testMetaGson() throws Exception {
        final MetaDTO initial = new MetaDTO();
        initial.setId(id);
        initial.setSamlEntityId(samlEntityId);
        initial.setSamlMetadataUrl(samlMetadataUrl);
        initial.setName(name);
        initial.setOrganization(organization);
        initial.setCountryCode(countryCode);
        initial.setServiceDescription(serviceDescription);
        initial.setContactEmail(contactEmail);
        final String json = gson.toJson(initial);
        final MetaDTO mapped = gson.fromJson(json, MetaDTO.class);
        Assert.assertEquals(mapped.getId(), id);
        Assert.assertEquals(mapped.getSamlEntityId(), samlEntityId);
        Assert.assertEquals(mapped.getSamlMetadataUrl(), samlMetadataUrl);
        Assert.assertEquals(mapped.getName(), name);
        Assert.assertEquals(mapped.getOrganization(), organization);
        Assert.assertEquals(mapped.getCountryCode(), countryCode);
        Assert.assertEquals(mapped.getServiceDescription(), serviceDescription);
        Assert.assertEquals(mapped.getContactEmail(), contactEmail);
    }
    
    /**
     * Test {@link ErrorDTO} encoding and decoding.
     */
    @Test
    public void testErrorGson() {
        final ErrorDTO initial = new ErrorDTO();
        initial.setCode(code);
        initial.setFields(fields);
        initial.setMessage(message);
        final String json = gson.toJson(initial);
        final ErrorDTO mapped = gson.fromJson(json, ErrorDTO.class);
        Assert.assertEquals(mapped.getCode(), code);
        Assert.assertEquals(mapped.getFields(), fields);
        Assert.assertEquals(mapped.getMessage(), message);
    }

}
