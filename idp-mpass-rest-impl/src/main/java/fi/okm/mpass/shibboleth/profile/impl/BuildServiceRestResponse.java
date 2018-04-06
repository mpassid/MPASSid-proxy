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
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.profile.action.EventIds;
import org.opensaml.saml.ext.saml2mdui.Description;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.InformationURL;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.ChainingMetadataResolver;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import com.google.gson.Gson;

import fi.okm.mpass.shibboleth.rest.data.ServiceDTO;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.saml.metadata.RelyingPartyMetadataProvider;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.service.ReloadableService;
import net.shibboleth.utilities.java.support.service.ServiceableComponent;

/**
 * This action builds a response containing {@link ServiceDTO}s.
 */
public class BuildServiceRestResponse extends AbstractRestResponseAction {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BuildServiceRestResponse.class);

    /** The service which managed the reloading of metadata. */
    private final ReloadableService<MetadataResolver> service;
    
    /** The URL for the unsolicited SSO. */
    private String unsolicitedUrl;

    /**
     * Constructor.
     *
     * @param resolverService The service which managed the reloading of metadata.
     */
    public BuildServiceRestResponse(@Nonnull final ReloadableService<MetadataResolver> resolverService) {
        service = Constraint.isNotNull(resolverService, "MetadataResolver Service cannot be null");
    }
    
    /**
     * Set the URL for the unsolicited SSO.
     * @param prefix What to set.
     */
    public void setUnsolicitedUrl(final String url) {
        unsolicitedUrl = Constraint.isNotEmpty(url, "The unsolicited SSO URL cannot be empty");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        log.debug("Initializing");
        super.doInitialize();
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull public Event execute(@Nonnull final RequestContext springRequestContext) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        final HttpServletRequest httpRequest = getHttpServletRequest();
        pushHttpResponseProperties();
        final HttpServletResponse httpResponse = getHttpServletResponse();
        
        try {
            final Writer out = new OutputStreamWriter(httpResponse.getOutputStream(), "UTF-8");
            
            if (!HttpMethod.GET.toString().equals(httpRequest.getMethod())) {
                log.warn("{}: Unsupported method attempted {}", getLogPrefix(), httpRequest.getMethod());
                out.append(makeErrorResponse(HttpStatus.SC_METHOD_NOT_ALLOWED, httpRequest.getMethod()
                        + " not allowed", "Only GET is allowed"));
            } else {
                final List<ServiceDTO> response = new ArrayList<ServiceDTO>();
                ServiceableComponent<MetadataResolver> component = null;
                component = service.getServiceableComponent();
                if (null == component) {
                    log.error("{} Error accessing underlying metadata source: Invalid configuration.", 
                            getLogPrefix());
                } else {
                    final MetadataResolver resolver = component.getComponent();
                    if (resolver instanceof RelyingPartyMetadataProvider && 
                            ((RelyingPartyMetadataProvider)resolver).getEmbeddedResolver() 
                            instanceof ChainingMetadataResolver) {
                        final ChainingMetadataResolver embedded = 
                                (ChainingMetadataResolver)((RelyingPartyMetadataProvider)resolver).getEmbeddedResolver();
                        for (final MetadataResolver chained : embedded.getResolvers()) {
                            final Iterator<EntityDescriptor> iterator = ((IterableMetadataSource)chained).iterator();
                            while (iterator.hasNext()) {
                                final EntityDescriptor entity = iterator.next();
                                final List<RoleDescriptor> roleDescriptors = entity.getRoleDescriptors();
                                if (roleDescriptors != null && !roleDescriptors.isEmpty() && roleDescriptors.get(0) instanceof SPSSODescriptor) {
                                    final SPSSODescriptor spDescriptor = (SPSSODescriptor) roleDescriptors.get(0);
                                    final ServiceDTO service = new ServiceDTO();
                                    service.setId(entity.getID());
                                    final UIInfo uiInfo = getUIInfo(spDescriptor);
                                    if (uiInfo != null) {
                                        //TODO support languages
                                        service.setIconUrl(getLogoUrl(uiInfo, null));
                                        service.setTitle(getTitle(uiInfo, null));
                                        service.setDescription(getDescription(uiInfo, null));
                                        service.setServiceUrl(getServiceUrl(uiInfo, null));                                    
                                    }
                                    if (StringSupport.trimOrNull(unsolicitedUrl) != null) {
                                        service.setSsoUrl(unsolicitedUrl + "?providerId=" + entity.getEntityID());
                                    }
                                    if (StringSupport.trimOrNull(service.getId()) != null &&
                                            StringSupport.trimOrNull(service.getTitle()) != null &&
                                            StringSupport.trimOrNull(service.getServiceUrl()) != null) {
                                        response.add(service);
                                    }
                                } else {
                                    log.debug("{} No SPSSODescriptor found", getLogPrefix());
                                }
                            }
                        }
                        final Gson gson = new Gson();
                        final LocalizedResponse localizedResponse = new LocalizedResponse();
                        localizedResponse.setLang("FI");
                        localizedResponse.setResponse(response);
                        out.append(gson.toJson(localizedResponse));
                        httpResponse.setStatus(HttpStatus.SC_OK);
                    } else {
                        log.error("{} Unsupported metadata resolver, not IterableMetadataSource: {}", getLogPrefix(), resolver.getClass());
                        out.append(makeErrorResponse(HttpStatus.SC_NOT_IMPLEMENTED,
                                "Not implemented on the server side", ""));
                    }
                }
                if (null != component) {
                    component.unpinComponent();
                }
            }
            out.flush();
        } catch (IOException e) {
            log.error("{}: Could not encode the JSON response", getLogPrefix(), e);
            httpResponse.setStatus(HttpStatus.SC_SERVICE_UNAVAILABLE);
            return ActionSupport.buildEvent(this, EventIds.IO_ERROR);
        }
        return ActionSupport.buildProceedEvent(this);
    }
    
    protected UIInfo getUIInfo(final SPSSODescriptor spDescriptor) {
        final Extensions extensions = spDescriptor.getExtensions();
        if (extensions != null) {
            final List<XMLObject> children = extensions.getUnknownXMLObjects();
            if (children != null && !children.isEmpty()) {
                for (XMLObject child : children) {
                    log.debug("{} Found {}", getLogPrefix(), child.getElementQName());
                    if (UIInfo.DEFAULT_ELEMENT_LOCAL_NAME.equals(child.getElementQName().getLocalPart()) && 
                            UIInfo.DEFAULT_ELEMENT_NAME.getNamespaceURI().equals(child.getElementQName().getNamespaceURI())) {
                        log.debug("{} Found UIInfo", getLogPrefix());
                        return (UIInfo) child;
                    }
                }
            } else {
                log.debug("{} Could not find any elements from Extensions", getLogPrefix());
            }
        }
        return null;
    }
    
    protected String getLogoUrl(final UIInfo uiInfo, final String lang) {
        final List<Logo> logos = uiInfo.getLogos();
        if (logos == null || logos.isEmpty()) {
            return null;
        }
        for (final Logo logo : logos) {
            if (logo.getXMLLang() != null && logo.getXMLLang().equals(lang)) {
                return logo.getURL();
            }
        }
        return logos.get(0).getURL();
    }
    
    protected String getDescription(final UIInfo uiInfo, final String lang) {
       final List<Description> descriptions = uiInfo.getDescriptions();
       if (descriptions == null || descriptions.isEmpty()) {
           return null;
       }
       for (final Description description : descriptions) {
           if (description.getXMLLang() != null && description.getXMLLang().equals(lang)) {
               return description.getValue();
           }
       }
       return descriptions.get(0).getValue();
    }
    
    protected String getTitle(final UIInfo uiInfo, final String lang) {
        final List<DisplayName> displayNames = uiInfo.getDisplayNames();
        if (displayNames == null || displayNames.isEmpty()) {
            return null;
        }
        for (final DisplayName displayName : displayNames) {
            if (displayName.getXMLLang() != null && displayName.getXMLLang().equals(lang)) {
                return displayName.getValue();
            }
        }
        return displayNames.get(0).getValue();
    }

    protected String getServiceUrl(final UIInfo uiInfo, final String lang) {
        final List<InformationURL> urls = uiInfo.getInformationURLs();
        if (urls == null || urls.isEmpty()) {
            return null;
        }
        for (final InformationURL url : urls) {
            if (url.getXMLLang() != null && url.getXMLLang().equals(lang)) {
                return url.getValue();
            }
        }
        return urls.get(0).getValue();
    }

}
