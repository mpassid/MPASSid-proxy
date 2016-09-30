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

package fi.okm.mpass.shibboleth.profile.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.mockito.Mockito;
import org.opensaml.profile.action.EventIds;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.gson.Gson;

import fi.okm.mpass.shibboleth.rest.data.ErrorDTO;
import fi.okm.mpass.shibboleth.rest.data.MetaDTO;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link BuildMetaRestResponse}.
 */
public class BuildMetaRestResponseTest {

    /** The action to be tested. */
    private BuildMetaRestResponse action;

    /** The SAML entity ID in the {@link MetaDTO}. */
    private String entityId;

    /** The SAML metadata URL in the {@link MetaDTO}. */
    private String metadataUrl;

    /** The organization in the {@link MetaDTO}. */
    private String organization;

    /** The name in the {@link MetaDTO}. */
    private String name;

    /** The identifier in the {@link MetaDTO}. */
    private String id;

    /** The service description in the {@link MetaDTO}. */
    private String description;

    /** The country code in the {@link MetaDTO}. */
    private String countryCode;

    /** The contact email in the {@link MetaDTO}. */
    private String email;

    /**
     * Initialize test variables.
     * @throws ComponentInitializationException
     */
    @BeforeMethod
    public void initTests() throws ComponentInitializationException {
        entityId = "mockEntityId";
        metadataUrl = "mockMetadataUrl";
        organization = "mockOrganization";
        name = "mockName";
        id = "mockId";
        description = "mockDescription";
        countryCode = "fi";
        email = "mock.email@example.org";
        action = new BuildMetaRestResponse();
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod(HttpMethod.GET.toString());
        action.setHttpServletRequest(httpRequest);
        action.setHttpServletResponse(new MockHttpServletResponse());
    }

    /**
     * Runs action with unsupported HTTP method.
     * @throws UnsupportedEncodingException
     * @throws ComponentInitializationException
     */
    @Test
    public void testInvalidMethod() throws UnsupportedEncodingException, ComponentInitializationException {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod(HttpMethod.POST.toString());
        action.setHttpServletRequest(httpRequest);
        verifyErrorDTO(action, HttpStatus.SC_METHOD_NOT_ALLOWED);
    }

    /**
     * Runs action without {@link MetaDTO} source configured.
     * @throws UnsupportedEncodingException
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoSource() throws UnsupportedEncodingException, ComponentInitializationException {
        verifyErrorDTO(action, HttpStatus.SC_NOT_IMPLEMENTED);
    }

    /**
     * Runs action without ability to write the response.
     * @throws ComponentInitializationException
     * @throws IOException
     */
    @Test
    public void testIOException() throws ComponentInitializationException, IOException {
        HttpServletResponse mockResponse = Mockito.mock(HttpServletResponse.class);
        Mockito.doThrow(new IOException("mockException")).when(mockResponse).getOutputStream();
        action.setHttpServletResponse(mockResponse);
        action.initialize();
        ActionTestingSupport.assertEvent(action.execute((RequestContext) null), EventIds.IO_ERROR);
    }

    /**
     * Runs action successfully.
     * @throws UnsupportedEncodingException
     * @throws ComponentInitializationException
     */
    @Test
    public void testWithSource() throws UnsupportedEncodingException, ComponentInitializationException {
        final MetaDTO metaDTO = new MetaDTO();
        metaDTO.setId(id);
        metaDTO.setName(name);
        action.setMetaDTO(metaDTO);
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute((RequestContext) null));
        final MockHttpServletResponse httpResponse = (MockHttpServletResponse) action.getHttpServletResponse();
        Assert.assertNotNull(httpResponse.getContentAsString());
        Assert.assertEquals(httpResponse.getStatus(), HttpStatus.SC_OK);
        final Gson gson = new Gson();
        final MetaDTO resultDTO = gson.fromJson(httpResponse.getContentAsString(), MetaDTO.class);
        Assert.assertEquals(resultDTO.getId(), metaDTO.getId());
        Assert.assertEquals(resultDTO.getSamlEntityId(), metaDTO.getSamlEntityId());
        Assert.assertEquals(resultDTO.getContactEmail(), metaDTO.getContactEmail());
        Assert.assertEquals(resultDTO.getCountryCode(), metaDTO.getCountryCode());
        Assert.assertEquals(resultDTO.getName(), metaDTO.getName());
        Assert.assertEquals(resultDTO.getSamlMetadataUrl(), metaDTO.getSamlMetadataUrl());
        Assert.assertEquals(resultDTO.getServiceDescription(), metaDTO.getServiceDescription());
        Assert.assertEquals(resultDTO.getOrganization(), metaDTO.getOrganization());
    }

    /**
     * Populate the {@link MetaDTO} contents.
     * @return
     */
    protected MetaDTO populateMetaDTO() {
        final MetaDTO metaDTO = new MetaDTO();
        metaDTO.setId(id);
        metaDTO.setSamlEntityId(entityId);
        metaDTO.setContactEmail(email);
        metaDTO.setCountryCode(countryCode);
        metaDTO.setName(name);
        metaDTO.setOrganization(organization);
        metaDTO.setSamlMetadataUrl(metadataUrl);
        metaDTO.setServiceDescription(description);
        return metaDTO;
    }

    /**
     * Verifies the {@link ErrorDTO} contents produced by the action.
     * @param action
     * @param code
     * @throws UnsupportedEncodingException
     * @throws ComponentInitializationException
     */
    protected void verifyErrorDTO(BuildMetaRestResponse action, int code)
            throws UnsupportedEncodingException, ComponentInitializationException {
        action.initialize();
        ActionTestingSupport.assertProceedEvent(action.execute((RequestContext) null));
        final MockHttpServletResponse httpResponse = (MockHttpServletResponse) action.getHttpServletResponse();
        Assert.assertNotNull(httpResponse.getContentAsString());
        final Gson gson = new Gson();
        final ErrorDTO errorDTO = gson.fromJson(httpResponse.getContentAsString(), ErrorDTO.class);
        Assert.assertEquals(httpResponse.getStatus(), code);
        Assert.assertNotNull(errorDTO);
        Assert.assertEquals(errorDTO.getCode(), code);
    }

}
