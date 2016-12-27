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

package fi.okm.mpass.idp.authn.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.Prompt.Type;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * An action that sets oidc information to
 * {@link SocialUserOpenIdConnectContext} and attaches it to
 * {@link AuthenticationContext}.
 */
@SuppressWarnings("rawtypes")
public class SetOIDCInformation extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SetOIDCInformation.class);

    /** Redirect URI. */
    private URI redirectURI;

    /** Client Id. */
    @Nonnull
    private ClientID clientID;

    /** Client Secret. */
    @Nonnull
    private Secret clientSecret;

    /** Response type, default is code flow. */
    @Nonnull
    private ResponseType responseType = new ResponseType(ResponseType.Value.CODE);

    /** Scope. */
    @Nonnull
    private Scope scope = new Scope(OIDCScopeValue.OPENID);

    /** OIDC Prompt. */
    private Prompt prompt;

    /** OIDC Authentication Class Reference values. */
    private List<ACR> acrs;

    /** OIDC Display. */
    private Display display;

    /** OIDC provider metadata. */
    private OIDCProviderMetadata oIDCProviderMetadata;

    /**
     * Sets the response type. Default is code. *
     * 
     * @param type
     *            space-delimited list of one or more authorisation response
     *            types.
     * @throws ParseException
     *             if response type cannot be parsed
     */
    public void setResponseType(String type) throws ParseException {
        log.trace("Entering & Leaving");
        this.responseType = ResponseType.parse(type);
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param oauth2ClientId
     *            Oauth2 Client ID
     */
    public void setClientId(String oauth2ClientId) {
        log.trace("Entering & Leaving");
        this.clientID = new ClientID(oauth2ClientId);
    }

    /**
     * Setter for Oauth2 Client secret.
     * 
     * @param oauth2ClientSecret
     *            Oauth2 Client Secret
     */
    public void setClientSecret(String oauth2ClientSecret) {
        log.trace("Entering & Leaving");
        this.clientSecret = new Secret(oauth2ClientSecret);
    }

    /**
     * Setter for OAuth2 redirect uri for provider to return to.
     * 
     * @param redirect
     *            OAuth2 redirect uri
     */

    public void setRedirectURI(URI redirect) {
        this.redirectURI = redirect;
    }

    /**
     * Setter for OpenId Provider Metadata location.
     * 
     * @param metadataLocation
     *            OpenId Provider Metadata location
     * @throws URISyntaxException
     *             if metadataLocation is not URI
     * @throws IOException
     *             if metadataLocation cannot be read
     * @throws ParseException
     *             if metadataLocation has wrong content
     */
    public void setProviderMetadataLocation(String metadataLocation) throws URISyntaxException, IOException,
            ParseException {
        log.trace("Entering");
        URI issuerURI = new URI(metadataLocation);
        URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration").toURL();
        InputStream stream = providerConfigurationURL.openStream();
        String providerInfo = null;
        try (java.util.Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        }
        oIDCProviderMetadata = OIDCProviderMetadata.parse(providerInfo);
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Scope values.
     * 
     * @param oidcScopes
     *            OpenId Scope values
     */
    public void setScope(List<String> oidcScopes) {
        log.trace("Entering");
        for (String oidcScope : oidcScopes) {
            switch (oidcScope.toUpperCase()) {
            case "ADDRESS":
                this.scope.add(OIDCScopeValue.ADDRESS);
                break;
            case "EMAIL":
                this.scope.add(OIDCScopeValue.EMAIL);
                break;
            case "OFFLINE_ACCESS":
                this.scope.add(OIDCScopeValue.OFFLINE_ACCESS);
                break;
            case "PHONE":
                this.scope.add(OIDCScopeValue.PHONE);
                break;
            case "PROFILE":
                this.scope.add(OIDCScopeValue.PROFILE);
                break;
            default:
            }
        }
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Prompt value.
     * 
     * @param oidcPrompt
     *            OpenId Prompt values
     */
    public void setPrompt(String oidcPrompt) {
        log.trace("Entering");
        this.prompt = new Prompt(oidcPrompt);
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId ACR values.
     * 
     * @param oidcAcrs
     *            OpenId ACR values
     */
    public void setAcr(List<String> oidcAcrs) {
        log.trace("Entering");
        for (String oidcAcr : oidcAcrs) {
            ACR acr = new ACR(oidcAcr);
            if (this.acrs == null) {
                this.acrs = new ArrayList<ACR>();
            }
            this.acrs.add(acr);
        }
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Display value.
     * 
     * @param oidcDisplay
     *            OpenId Display values
     */
    public void setDisplay(String oidcDisplay) {
        log.trace("Entering");
        try {
            this.display = Display.parse(oidcDisplay);
        } catch (ParseException e) {
            log.error("Could not set display value", e);
        }
        log.trace("Leaving");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final SocialUserOpenIdConnectContext suCtx = authenticationContext.getSubcontext(
                SocialUserOpenIdConnectContext.class, true);

        // We initialize the context
        // If request is passive we override default prompt value
        Prompt ovrPrompt = authenticationContext.isPassive() ? new Prompt(Type.NONE) : prompt;
        suCtx.setPrompt(ovrPrompt);
        suCtx.setAcrs(acrs);
        suCtx.setClientID(clientID);
        suCtx.setClientSecret(clientSecret);
        suCtx.setDisplay(display);
        suCtx.setoIDCProviderMetadata(oIDCProviderMetadata);
        suCtx.setRedirectURI(redirectURI);
        State state = new State();
        suCtx.setState(state);
        Nonce nonce = new Nonce();
        suCtx.setNonce(nonce);
        if (authenticationContext.isForceAuthn()) {
            // We set max age to 0 if forcedauth is set
            // TODO: Currently the underlying library doesn't accept value 0, so
            // we set it to 1
            final int maxAge = 1;
            if (responseType.equals(ResponseType.Value.CODE)) {
                suCtx.setAuthenticationRequestURI(new AuthenticationRequest.Builder(responseType, scope, clientID,
                        redirectURI).endpointURI(oIDCProviderMetadata.getAuthorizationEndpointURI()).display(display)
                        .acrValues(acrs).maxAge(maxAge).prompt(ovrPrompt).state(state).nonce(nonce).build().toURI());
            } else {
                suCtx.setAuthenticationRequestURI(new AuthenticationRequest.Builder(responseType, scope, clientID,
                        redirectURI).endpointURI(oIDCProviderMetadata.getAuthorizationEndpointURI()).display(display)
                        .acrValues(acrs).responseMode(ResponseMode.QUERY).maxAge(maxAge).prompt(ovrPrompt).state(state)
                        .nonce(nonce).build().toURI());
            }
        } else {
            if (responseType.equals(ResponseType.Value.CODE)) {
                suCtx.setAuthenticationRequestURI(new AuthenticationRequest.Builder(responseType, scope, clientID,
                        redirectURI).endpointURI(oIDCProviderMetadata.getAuthorizationEndpointURI()).display(display)
                        .acrValues(acrs).prompt(ovrPrompt).state(state).nonce(nonce).build().toURI());
            } else {
                suCtx.setAuthenticationRequestURI(new AuthenticationRequest.Builder(responseType, scope, clientID,
                        redirectURI).endpointURI(oIDCProviderMetadata.getAuthorizationEndpointURI()).display(display)
                        .acrValues(acrs).responseMode(ResponseMode.QUERY).prompt(ovrPrompt).state(state).nonce(nonce)
                        .build().toURI());
            }
        }

        log.trace("Leaving");
        return;
    }

}
