# Shibboleth IdP v3: Shibboleth SP authentication

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home) exploiting attributes provided by 
[Shibboleth Service Provider](https://shibboleth.net/products/service-provider.html). The module can be used
for outsourcing the authentication to another SAML IdP instead of prompting and validating the user
credentials itself.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-shibsp
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-shibsp-\<version\>-bin_
subdirectory.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Also, the module's authentication flow and its bean definitions must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
cp target/idp-authn-impl-shibsp-<version>-bin/idp-authn-impl-shibsp-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r target/idp-authn-impl-shibsp-<version>-bin/idp-authn-impl-shibsp-<version>/flows /opt/shibboleth-idp/flows
cp target/idp-authn-impl-shibsp-<version>-bin/idp-authn-impl-shibsp-<version>/conf/* /opt/shibboleth-idp/conf/authn
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

The desired [Shibboleth SP Handler](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPHandler)
location and its parameters are configured in the file _/opt/shibboleth-idp/conf/authn/shib-authn-config.xml_.
The default configuration is referred as _shibboleth.authn.Shib.externalAuthnPath_, which is also referred by
the flow definition file (_/opt/shibboleth-idp/flows/authn/Shib/Shib-flow.xml_). It's possible to configure
multiple flows with different SP Handler configurations, or support multiple IdPs for instance via
[Shibboleth Embedded Discovery Service]
(https://wiki.shibboleth.net/confluence/display/EDS10/Embedded+Discovery+Service).

Finally, you will need to add the new authentication flow definition(s) to _/opt/shibboleth-idp/conf/authn/general-authn.xml_:

```
<bean id="authn/Shib" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
```
