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

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.entity.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

import fi.okm.mpass.shibboleth.rest.data.ErrorDTO;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.net.HttpServletSupport;

/**
 * A base class for actions publishing JSON information.
 */
@SuppressWarnings("rawtypes")
public class AbstractRestResponseAction extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractRestResponseAction.class);
    
    /**
     * Push common REST/JSON settings to {@link HttpServletResponse}.
     */
    protected void pushHttpResponseProperties() {
        final HttpServletResponse httpResponse = getHttpServletResponse();
        HttpServletSupport.addNoCacheHeaders(httpResponse);
        HttpServletSupport.setUTF8Encoding(httpResponse);
        HttpServletSupport.setContentType(httpResponse, ContentType.APPLICATION_JSON.toString());
    }

    /**
     * Helper method for constructing a {@link ErrorDTO} with desired content and returning it as JSON
     * string. The given code is also set as a status for {@link HttpServletResponse}.
     * 
     * @param code The status code of the error.
     * @param message The message of the error.
     * @param fields The fields for the error.
     * @return
     */
    protected String makeErrorResponse(final int code, final String message, final String fields) {
        final ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(message);
        errorDTO.setFields(fields);
        getHttpServletResponse().setStatus(code);
        final Gson gson = new Gson();
        return gson.toJson(errorDTO);
    }
    
    /**
     * The DTO class for localized response.
     */
    protected class LocalizedResponse {
        
        /** The language used in the response. */
        private String lang;
        
        /** The response. */
        private Object response;
        
        /**
         * Get the language used in the response.
         * @return The language used in the response.
         */
        public String getLang() {
            return lang;
        }
        
        /**
         * Set the language used in the response.
         * @param language What to set.
         */
        public void setLang(final String language) {
            lang = language;
        }
        
        /**
         * Get the response.
         * @return The response.
         */
        public Object getResponse() {
            return response;
        }
        
        /**
         * Set the response.
         * @param resp What to set.
         */
        public void setResponse(final Object resp) {
            response = resp;
        }
    }
}
