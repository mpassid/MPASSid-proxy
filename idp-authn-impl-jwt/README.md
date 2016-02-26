# Shibboleth IdP v3: JWT authentication

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home) exploiting attributes provided by 
3rd party via JWT token.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-jwt
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-jwt-\<version\>-bin_
subdirectory.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Also, the module's authentication flow and its bean definitions must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
cp target/idp-authn-impl-jwt-<version>-bin/idp-authn-impl-jwt-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r target/idp-authn-impl-jwt-<version>-bin/idp-authn-impl-jwt-<version>/flows/* /opt/shibboleth-idp/flows
cp target/idp-authn-impl-jwt-<version>-bin/idp-authn-impl-jwt-<version>/conf/* /opt/shibboleth-idp/conf/authn
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

TODO: Finalize documentation
