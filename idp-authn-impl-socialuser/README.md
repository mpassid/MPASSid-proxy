# Shibboleth IdP Social User authentication extensions

## Overview

This module contains implementations of Facebook, Google, LinkedIn, Twitter, Yle, OAuth2 and OpenID Connect authentication modules for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Authentication modules

### Authentication concerns
- By their very nature, these modules do create (if not pre-existing) a authenticated session not only to IdP but also to the social identity provider. Logging out of SP or IdP does not logout user from the social identity provider. 
- Not all of these modules support forced authentication. We hope to add that to as many as we can. The case of not using forced authentication combined with a browser shared by many is problematic. In such cases users must be instructed to use private browsing and to close that browser in the end. 

### Spring Social modules
There are four modules implemented using Spring Social.  

#### Facebook
- Template for bean definition in socialuser-authn-beans.xml: FacebookIdentity
- This module supports forced authentication.

#### Google
- Template for bean definition in socialuser-authn-beans.xml: GoogleIdentity
- This module does not support forced authentication.

#### LinkedIn
- Template for bean definition in socialuser-authn-beans.xml: LinkedInIdentity
- This module does not support forced authentication.

#### Twitter
- Template for bean definition in socialuser-authn-beans.xml: TwitterIdentity
- This module supports forced authentication.

### Nimbus modules
There are three modules implemented using Nimbus OAuth2 SDK.  

#### OAuth2 
- Template for bean definition in socialuser-authn-beans.xml: ExampleOauth2Identity
- This module does not support forced authentication by default.

#### OpenID Connect
- Template for bean definition in socialuser-authn-beans.xml: ExampleOpenIdConnectIdentity
- This module does not support forced authentication by default.

#### Yle (Finnish Broadcasting Company)
- Template for bean definition in socialuser-authn-beans.xml: OAuth2YleIdentity
- This module does not support forced authentication.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-socialuser
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-socialuser-\<version\>.jar_ and some assemblies.

## Deployment

After compilation, the _target/idp-authn-api-socialuser-\<version\>.jar_ must be deployed to the IdP Web application and it must be configured. Depending on the IdP installation, the module deployment may be achieved for instance with the following sequence:

```
cp target/idp-authn-impl-socialuser-\<version\>-bin/idp-authn-impl-socialuser-\<version\>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib/.
cd /opt/shibboleth-idp
sh bin/build.sh
cp -r target/idp-authn-impl-socialuser-\<version\>-bin/idp-authn-impl-socialuser-\<version\>/conf /opt/shibboleth-idp/conf
cp -r target/idp-authn-impl-socialuser-\<version\>-bin/idp-authn-impl-socialuser-\<version\>/flows /opt/shibboleth-idp/flows
```

The second final command will rebuild the _war_-package for the IdP application.

The copied flows/beans will not work unless you configure them:

1. You will need to define the OAUTH1/OAUTH2 parameters for the  authentication beans defined in /opt/shibboleth-idp/flows/authn/SocialUser/socialuser-authn-beans.xml. Those beans will need to be mapped in SocialUserImplementationFactory bean defined in the same file. 
2. You will need to add the new authentication flows to /opt/shibboleth-idp/conf/authn/general-authn.xml

```
<bean id="authn/SocialUserTwitter" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
<bean id="authn/SocialUserFacebook" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>       
<bean id="authn/SocialUserGoogle" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" />
<bean id="authn/SocialUserLinkedIn" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" />
```
3. /opt/shibboleth-idp/conf/attribute-resolver-social.xml has example attribute definitions
4. New authentication flow can now be used by defining it to idp.properties file