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

import com.google.gson.annotations.SerializedName;

/**
 * Data transfer object for the meta information of an MPASSid proxy.
 */
public class MetaDTO {

    /** The identifier. */
    private String id;

    /** The SAML entity ID. */
    @SerializedName("saml_entity_id")
    private String samlEntityId;

    /** The URL for fetching SAML metadata. */
    @SerializedName("saml_metadata_url")
    private String samlMetadataUrl;

    /** The human readable name of the proxy. */
    private String name;

    /** The organization running the proxy. */
    @SerializedName("organisation")    
    private String organization;

    /** The country code for the proxy. */
    @SerializedName("country_code")
    private String countryCode;

    /** The service description of the proxy. */
    @SerializedName("service_description")
    private String serviceDescription;

    /** The contact email address of the proxy. */
    @SerializedName("contact_email")
    private String contactEmail;

    /**
     * Get the identifier.
     * @return The identifier.
     */
    public String getId() {
        return id;
    }

    /**
     * Set the identifier.
     * @param newId What to set.
     */
    public void setId(final String newId) {
        this.id = newId;
    }

    /**
     * Get the SAML entity ID.
     * @return The SAML entity ID.
     */
    public String getSamlEntityId() {
        return samlEntityId;
    }

    /**
     * Set the SAML entity ID.
     * @param entityId What to set.
     */
    public void setSamlEntityId(final String entityId) {
        this.samlEntityId = entityId;
    }

    /**
     * Get the URL for fetching SAML metadata.
     * @return The URL for fetching SAML metadata.
     */
    public String getSamlMetadataUrl() {
        return samlMetadataUrl;
    }

    /**
     * Set the URL for fetching SAML metadata.
     * @param metadataUrl What to set.
     */
    public void setSamlMetadataUrl(final String metadataUrl) {
        this.samlMetadataUrl = metadataUrl;
    }

    /**
     * Get the human readable name of the proxy.
     * @return The human readable name of the proxy.
     */
    public String getName() {
        return name;
    }

    /**
     * Set the human readable name of the proxy.
     * @param newName What to set.
     */
    public void setName(final String newName) {
        this.name = newName;
    }

    /**
     * Get the organization running the proxy.
     * @return The organization running the proxy.
     */
    public String getOrganization() {
        return organization;
    }

    /**
     * Set organization running the proxy.
     * @param newOrganization What to set.
     */
    public void setOrganization(final String newOrganization) {
        this.organization = newOrganization;
    }

    /**
     * Get the country code for the proxy.
     * @return The country code for the proxy.
     */
    public String getCountryCode() {
        return countryCode;
    }

    /**
     * Set the country code for the proxy.
     * @param code What to set.
     */
    public void setCountryCode(final String code) {
        this.countryCode = code;
    }

    /**
     * Get the service description of the proxy.
     * @return The service description of the proxy.
     */
    public String getServiceDescription() {
        return serviceDescription;
    }

    /**
     * Set the service description of the proxy.
     * @param description What to set.
     */
    public void setServiceDescription(final String description) {
        this.serviceDescription = description;
    }

    /**
     * Get the contact email address of the proxy.
     * @return The contact email address of the proxy.
     */
    public String getContactEmail() {
        return contactEmail;
    }

    /**
     * Set the contact email address of the proxy.
     * @param email What to set.
     */
    public void setContactEmail(final String email) {
        this.contactEmail = email;
    }
}