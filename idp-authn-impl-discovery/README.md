# Shibboleth IdP Authn Flow Discovery

## Overview

This module implements a simple authentication method selection flow for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home). The module can be used for first displaying all
the available authentication flows and then proceeding with the user-selected authentication flow.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-discovery
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-discovery-\<version\>.jar_.

## Deployment

After compilation, the _target/idp-authn-impl-discovery-\<version\>.jar_ must be deployed to the IdP Web
application. Also, the module's authentication flow, its bean definitions and view (user interface) must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
cp target/idp-authn-impl-discovery-1.0-SNAPSHOT.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r target/idp-authn-impl-discovery-\<version\>-bin/idp-authn-impl-discovery-\<version\>/flows /opt/shibboleth-idp/flows
cp -r target/idp-authn-impl-discovery-\<version\>-bin/idp-authn-impl-discovery-\<version\>/views /opt/shibboleth-idp/views
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

Finally, you will need to add the new authentication flow definition to _/opt/shibboleth-idp/conf/authn/general-authn.xml_:

```
<bean id="authn/Disco" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
```
            