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

public class MetaDTO {

    private String id;

    @SerializedName("saml_entity_id")
    private String samlEntityId;

    @SerializedName("saml_metadata_url")
    private String samlMetadataUrl;

    private String name;

    @SerializedName("organisation")    
    private String organization;

    @SerializedName("country_code")
    private String countryCode;

    @SerializedName("service_description")
    private String serviceDescription;

    @SerializedName("contact_email")
    private String contactEmail;

    public String getId() {
        return id;
    }

    public void setId(final String newId) {
        this.id = newId;
    }

    public String getSamlEntityId() {
        return samlEntityId;
    }

    public void setSamlEntityId(final String entityId) {
        this.samlEntityId = entityId;
    }

    public String getSamlMetadataUrl() {
        return samlMetadataUrl;
    }

    public void setSamlMetadataUrl(final String metadataUrl) {
        this.samlMetadataUrl = metadataUrl;
    }

    public String getName() {
        return name;
    }

    public void setName(final String newName) {
        this.name = newName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(final String newOrganization) {
        this.organization = newOrganization;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(final String code) {
        this.countryCode = code;
    }

    public String getServiceDescription() {
        return serviceDescription;
    }

    public void setServiceDescription(final String description) {
        this.serviceDescription = description;
    }

    public String getContactEmail() {
        return contactEmail;
    }

    public void setContactEmail(final String email) {
        this.contactEmail = email;
    }

}
