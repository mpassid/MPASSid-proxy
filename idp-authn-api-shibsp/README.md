# ECA Proxy: Shibboleth SP authentication API

## Overview

This module contains interface classes for [idp-authn-impl-shibsp]
(https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-authn-impl-shibsp). These two modules can
be used for adding SAML -based Identity Providers as authentication methods for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Prequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-api-shibsp
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-api-shibsp-\<version\>.jar_.

## Deployment

After compilation, the _target/idp-authn-api-shibsp-\<version\>.jar_ must be deployed to the IdP Web
application. Depending on the IdP installation, the module deployment may be achieved for instance with the
following sequence:

```
cp target/idp-authn-api-shibsp-1.0-SNAPSHOT.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.
