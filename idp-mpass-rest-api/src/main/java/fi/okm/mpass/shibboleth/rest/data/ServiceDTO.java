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

/**
 * Data transfer object for the information about one service.
 */
public class ServiceDTO extends TitledDTO {

    /** The service URL. */
    private String serviceUrl;
    
    /** The (unsolicited) SSO URL for this service. */
    private String ssoUrl;
    
    /** The description for this service. */
    private String description;

    /** The icon URL for this service. */
    private String iconUrl;

    /**
     * Get the service URL.
     * @return The service URL.
     */
    public String getServiceUrl() {
        return serviceUrl;
    }

    /**
     * Set the service URL.
     * @param serviceUrl What to set.
     */
    public void setServiceUrl(String serviceUrl) {
        this.serviceUrl = serviceUrl;
    }

    /**
     * Get the (unsolicited) SSO URL for this service.
     * @return The (unsolicited) SSO URL for this service.
     */
    public String getSsoUrl() {
        return ssoUrl;
    }

    /**
     * Set the (unsolicited) SSO URL for this service.
     * @param url What to set.
     */
    public void setSsoUrl(String url) {
        this.ssoUrl = url;
    }

    /**
     * Get the description for this service.
     * @return The description for this service.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Set the description for this service.
     * @param desc What to set.
     */
    public void setDescription(String desc) {
        this.description = desc;
    }
  
    /**
     * Get the icon URL for this service.
     * @return The icon URL for this service.
     */
    public String getIconUrl() {
        return iconUrl;
    }

    /**
     * Set the icon URL for this service.
     * @param iconUrl What to set.
     */
    public void setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
    }
}
