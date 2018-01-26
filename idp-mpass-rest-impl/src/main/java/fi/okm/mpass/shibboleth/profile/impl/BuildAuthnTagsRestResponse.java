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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.okm.mpass.shibboleth.rest.data.AuthnTagDTO;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * This action builds a response containing {@link AuthnTagDTO}s.
 */
public class BuildAuthnTagsRestResponse extends AbstractAuthnFlowRestResponseAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(BuildAuthnTagsRestResponse.class);

    /** The full flow information to be responded by the API. */
    private Map<String, List<AuthnTagDTO>> tagInformation;

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        log.debug("Initializing");
        super.doInitialize();
        tagInformation = new HashMap<>();
        for (final String locale : getSupportedLocales()) {
            tagInformation.put(locale, new ArrayList<AuthnTagDTO>());
        }
        for (final AuthenticationFlowDescriptor flow : getFlows()) {
            final String id = (flow.getId().startsWith("authn")) ? flow.getId().substring(6) : flow.getId();
            if (getActiveFlowIds().contains(id) && !isIgnoredFlow(flow, id)) {
                log.debug("{} Adding details from flow {}", getLogPrefix(), id);
                final List<String> tagIds = getTags(flow, id);
                for (final String tagId : tagIds) {
                    boolean found = false;
                    for (final AuthnTagDTO tag : tagInformation.get(tagInformation.keySet().iterator().next())) {
                        if (tag.getId().equals(tagId)) {
                            found = true;
                        }
                    }
                    if (!found) {
                        final String titleProperty = getAdditionalInfo().getProperty(tagId + ".title");
                        log.trace("{} Resolving a localized {}", getLogPrefix(), titleProperty);
                        for (final String locale : getSupportedLocales()) {
                            tagInformation.get(locale).add(new AuthnTagDTO(tagId, getMessageSource()
                                    .getMessage(titleProperty, null, Locale.forLanguageTag(locale))));
                        }
                        log.debug("{} Added a tag {} to be returned", getLogPrefix(), tagId);
                    }
                }
            } else {
                log.trace("{} Ignoring {}", getLogPrefix(), id);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    protected Object getResponse(final String lang) {
        return tagInformation.get(lang);
    }
}