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

import java.util.List;

/**
 * Data transfer object for the information about authentication source.
 */
public class AuthnSourceDTO extends TitledDTO {
    
    /** The tags for this authentication source. */
    private List<String> tags;
    
    /** The icon URL for this authentication source. */
    private String iconUrl;
    
    /** Flag whether this authentication source is directly connected to user registry. */
    private boolean directRegistryConnection;
    
    /** Flag whether this authentication source supports forced authentication. */
    private boolean supportsForced;
    
    /** Flag whether this authentication source supports passive authentication. */
    private boolean supportsPassive;
    
    /**
     * Constructor.
     *
     * @param id The identifier for this authentication source.
     * @param title The human-readable title reference for this authentication source.
     * @param tags The tags for this authentication source.
     * @param iconUrl The icon URL for this authentication source.
     * @param directRegistryConnection Flag whether this authentication source is directly connected to user registry.
     * @param supportsForced Flag whether this authentication source supports forced authentication.
     * @param supportsPassive Flag whether this authentication source supports passive authentication.
     */
    public AuthnSourceDTO(final String id, final String title, final List<String> tags, final String iconUrl, 
            final boolean directRegistryConnection, final boolean supportsForced, final boolean supportsPassive) {
        setId(id);
        setTitle(title);
        setTags(tags);
        setIconUrl(iconUrl);
        setDirectRegistryConnection(directRegistryConnection);
        setSupportsForced(supportsForced);
        setSupportsPassive(supportsPassive);
    }

    /**
     * @return Returns the tags.
     */
    public List<String> getTags() {
        return tags;
    }

    /**
     * @param tags The tags to set.
     */
    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    /**
     * @return Returns the iconUrl.
     */
    public String getIconUrl() {
        return iconUrl;
    }

    /**
     * @param iconUrl The iconUrl to set.
     */
    public void setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
    }

    /**
     * @return Returns the notDirect.
     */
    public boolean isDirectRegistryConnection() {
        return directRegistryConnection;
    }

    /**
     * @param notDirect The notDirect to set.
     */
    public void setDirectRegistryConnection(boolean notDirect) {
        this.directRegistryConnection = notDirect;
    }

    /**
     * @return Returns the supportsForced.
     */
    public boolean isSupportsForced() {
        return supportsForced;
    }

    /**
     * @param supportsForced The supportsForced to set.
     */
    public void setSupportsForced(boolean supportsForced) {
        this.supportsForced = supportsForced;
    }

    /**
     * @return Returns the supportsPassive.
     */
    public boolean isSupportsPassive() {
        return supportsPassive;
    }

    /**
     * @param supportsPassive The supportsPassive to set.
     */
    public void setSupportsPassive(boolean supportsPassive) {
        this.supportsPassive = supportsPassive;
    }

}