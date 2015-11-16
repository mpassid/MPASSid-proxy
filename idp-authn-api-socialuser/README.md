# Shibboleth IdP Social User authentication API

## Overview

This module contains interface classes for [idp-authn-impl-socialuser](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-authn-impl-socialuser). These two modules can
be used for adding Social based authentication methods for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-api-socialuser
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-api-socialuser-\<version\>.jar_.

## Deployment

If you are deploying [idp-authn-impl-socialuser](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-authn-impl-socialuser),please refer to those deployment instructions only. 
Otherwise, after compilation, the _target/idp-authn-api-socialuser-\<version\>.jar_ must be deployed to the IdP Web application. Depending on the IdP installation, the module deployment may be achieved for instance with the following sequence:

```
cp target/idp-authn-api-idp-authn-api-socialuser-1.0-SNAPSHOT.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.
